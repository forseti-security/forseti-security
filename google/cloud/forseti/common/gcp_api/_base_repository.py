# Copyright 2017 The Forseti Security Authors. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Base GCP client which uses the discovery API."""
import json
import logging
import os
import threading
from urlparse import urljoin

import google_auth_httplib2
import googleapiclient
from googleapiclient import discovery
from ratelimiter import RateLimiter
from retrying import retry
import uritemplate

import google.auth
from google.auth.credentials import with_scopes_if_required

from google.cloud.forseti.common.gcp_api import _supported_apis
from google.cloud.forseti.common.gcp_api import errors as api_errors
from google.cloud.forseti.common.util import http_helpers
from google.cloud.forseti.common.util import logger
from google.cloud.forseti.common.util import replay
from google.cloud.forseti.common.util import retryable_exceptions
import google.oauth2.credentials

CLOUD_SCOPES = frozenset(['https://www.googleapis.com/auth/cloud-platform'])

# Per thread storage.
LOCAL_THREAD = threading.local()

LOGGER = logger.get_logger(__name__)

# Default value num_retries within HttpRequest execute method
NUM_HTTP_RETRIES = 5

# Support older versions of apiclient without cache support
SUPPORT_DISCOVERY_CACHE = (googleapiclient.__version__ >= '1.4.2')

# Used by the record and replay decorator to store requests across all repos.
REQUEST_RECORDER = dict()
REQUEST_REPLAYER = dict()

# Used for private APIs that need to be created from local discovery documents
DISCOVERY_DOCS_BASE_DIR = os.path.join(os.path.abspath(
    os.path.dirname(__file__)), 'discovery_documents')


@retry(retry_on_exception=retryable_exceptions.is_retryable_exception,
       wait_exponential_multiplier=1000, wait_exponential_max=10000,
       stop_max_attempt_number=5)
def _create_service_api(credentials, service_name, version, is_private_api,
                        developer_key=None, cache_discovery=False,
                        use_versioned_discovery_doc=False):
    """Builds and returns a cloud API service object.

    Args:
        credentials (OAuth2Credentials): Credentials that will be used to
            authenticate the API calls.
        service_name (str): The name of the API.
        version (str): The version of the API to use.
        is_private_api (bool): Whether the API is a private API.
        developer_key (str): The api key to use to determine the project
            associated with the API call, most API services do not require
            this to be set.
        cache_discovery (bool): Whether or not to cache the discovery doc.
        use_versioned_discovery_doc (bool): When set to true, will use the
            discovery doc with the version suffix in the filename.

    Returns:
        object: A Resource object with methods for interacting with the service.
    """
    # The default logging of the discovery obj is very noisy in recent versions.
    # Lower the default logging level of just this module to WARNING unless
    # debug is enabled.
    if LOGGER.getEffectiveLevel() > logging.DEBUG:
        logging.getLogger(discovery.__name__).setLevel(logging.WARNING)

    # Used for private APIs that are built from a local discovery file
    if is_private_api:

        if use_versioned_discovery_doc:
            service_json = '{}_{}.json'.format(service_name, version)
        else:
            service_json = '{}.json'.format(service_name)

        service_path = os.path.join(DISCOVERY_DOCS_BASE_DIR, service_json)
        return _build_service_from_document(
            credentials,
            service_path)

    discovery_kwargs = {
        'serviceName': service_name,
        'version': version,
        'developerKey': developer_key,
        'credentials': credentials}
    if SUPPORT_DISCOVERY_CACHE:
        discovery_kwargs['cache_discovery'] = cache_discovery

    return discovery.build(**discovery_kwargs)


def _build_service_from_document(credentials, document_path):
    """Builds an API client from a local discovery document

    Args:
        credentials (OAuth2Credentials): Credentials that will be used to
            authenticate the API calls.
        document_path (str): The local path of the discovery document

    Returns:
        object: A Resource object with methods for interacting with the service.
    """
    with open(document_path, 'r') as f:
        discovery_data = json.load(f)

    return discovery.build_from_document(
        service=discovery_data,
        credentials=credentials
    )


# pylint: disable=too-many-instance-attributes
class BaseRepositoryClient(object):
    """Base class for API repository for a specified Cloud API."""

    def __init__(self,
                 api_name,
                 versions=None,
                 credentials=None,
                 quota_max_calls=None,
                 quota_period=None,
                 use_rate_limiter=False,
                 read_only=False,
                 use_versioned_discovery_doc=False,
                 **kwargs):
        """Constructor.

        Args:
            api_name (str): The API name to wrap. More details here:
                  https://developers.google.com/api-client-library/python/apis/
            versions (list): A list of version strings to initialize.
            credentials (object): GoogleCredentials.
            quota_max_calls (int): Allowed requests per <quota_period> for the
                API.
            quota_period (float): The time period to track requests over.
            use_rate_limiter (bool): Set to false to disable the use of a rate
                limiter for this service.
            read_only (bool): When set to true, disables any API calls that
                would modify a resource within the repository.
            use_versioned_discovery_doc (bool): When set to true, will use the
                discovery doc with the version suffix in the filename.
            **kwargs (dict): Additional args such as version.
        """
        self._use_cached_http = False
        if not credentials:
            # Only share the http object when using the default credentials.
            self._use_cached_http = True
            credentials, _ = google.auth.default()
        self._credentials = with_scopes_if_required(credentials,
                                                    list(CLOUD_SCOPES))

        # Lock may be acquired multiple times in the same thread.
        self._repository_lock = threading.RLock()

        if use_rate_limiter:
            self._rate_limiter = RateLimiter(max_calls=quota_max_calls,
                                             period=quota_period)
        else:
            self._rate_limiter = None

        self._read_only = read_only

        self.name = api_name

        # Look to see if the API is formally supported in Forseti.
        supported_api = _supported_apis.SUPPORTED_APIS.get(api_name)
        if not supported_api:
            LOGGER.warn('API "%s" is not formally supported in Forseti, '
                        'proceed at your own risk.', api_name)

        # See if the version is supported by Forseti.
        # If no version is specified, use the supported API's default version.
        if not versions and supported_api:
            versions = [supported_api.get('default_version')]
        self.versions = versions

        if supported_api:
            for version in versions:
                if version not in supported_api.get('supported_versions', []):
                    LOGGER.warn('API "%s" version %s is not formally supported '
                                'in Forseti, proceed at your own risk.',
                                api_name, version)

        self.is_private_api = None
        if supported_api:
            self.is_private_api = (
                _supported_apis.SUPPORTED_APIS.get(api_name)
                .get('is_private_api'))

        self.gcp_services = {}
        for version in versions:
            self.gcp_services[version] = _create_service_api(
                self._credentials,
                self.name,
                version,
                self.is_private_api,
                kwargs.get('developer_key'),
                kwargs.get('cache_discovery', False),
                use_versioned_discovery_doc)

    def __repr__(self):
        """The object representation.

        Returns:
            str: The object representation.
        """
        return 'API: name=%s, versions=%s' % (self.name, self.versions)

    def _init_repository(self, repository_class, version=None):
        """Safely initialize a repository class to a property.

        Args:
            repository_class (class): The class to initialize.
            version (str): The gcp service version for the repository.

        Returns:
            object: An instance of repository_class.
        """
        if not version:
            # Use either the default version if defined or the first version
            # returned when sorted by name.
            version = (
                _supported_apis.SUPPORTED_APIS.get(self.name, {})
                .get('default_version'))
            if not version or version not in self.gcp_services:
                version = sorted(self.gcp_services.keys())[0]

        with self._repository_lock:
            return repository_class(gcp_service=self.gcp_services[version],
                                    credentials=self._credentials,
                                    rate_limiter=self._rate_limiter,
                                    use_cached_http=self._use_cached_http,
                                    read_only=self._read_only)


# pylint: enable=too-many-instance-attributes
# pylint: disable=too-many-instance-attributes, too-many-arguments
# pylint: disable=too-many-locals
class GCPRepository(object):
    """Base class for GCP APIs."""

    def __init__(self, gcp_service, credentials, component,
                 num_retries=NUM_HTTP_RETRIES, key_field='project',
                 entity_field=None, list_key_field=None, get_key_field=None,
                 max_results_field='maxResults', search_query_field='query',
                 resource_path_template=None, rate_limiter=None,
                 use_cached_http=True, read_only=False):
        """Constructor.

        Args:
            gcp_service (object): A Resource object with methods for interacting
                with the service.
            credentials (OAuth2Credentials): A Credentials object
            component (str): The subcomponent of the gcp service for this
                repository instance. E.g. 'instances' for compute.instances().*
                APIs
            num_retries (int): The number of http retriable errors to retry on
                before hard failing.
            key_field (str): The field name representing the project to
                query in the API.
            entity_field (str): The API entity returned generally by the .get()
                api. E.g. 'instance' for compute.instances().get()
            list_key_field (str): Optional override of key field for calls to
                list methods.
            get_key_field (str): Optional override of key field for calls to
                get methods.
            max_results_field (str): The field name that represents the maximum
                number of results to return in one page.
            search_query_field (str): The field name used to filter search
                results.
            resource_path_template (str): The path to an individual resource
                object. Described in the discovery doc as the path for a method,
                and usually in the documentation for the API under the get
                request. This is used when creating fake responses when running
                in read only mode.
            rate_limiter (object): A RateLimiter object to manage API quota.
            use_cached_http (bool): If set to true, calls to the API will use
                a thread local shared http object. When false a new http object
                is used for each request.
            read_only (bool): When set to true, disables any API calls that
                would modify a resource within the repository.
        """
        self.gcp_service = gcp_service
        self.read_only = read_only

        self._credentials = credentials
        components = component.split('.')
        self._component = getattr(
            self.gcp_service, components.pop(0))()
        for nested_component in components:
            self._component = getattr(
                self._component, nested_component)()
        self._entity_field = entity_field
        self._num_retries = num_retries
        if list_key_field:
            self._list_key_field = list_key_field
        else:
            self._list_key_field = key_field
        if get_key_field:
            self._get_key_field = get_key_field
        else:
            self._get_key_field = key_field
        self._max_results_field = max_results_field
        self._search_query_field = search_query_field
        self._resource_path_template = resource_path_template
        self._rate_limiter = rate_limiter

        self._use_cached_http = use_cached_http
        self._local = LOCAL_THREAD

    @property
    def http(self):
        """A thread local instance of httplib2.Http.

        Returns:
            google_auth_httplib2.AuthorizedHttp: An Http instance authorized by
                the credentials.
        """
        if self._use_cached_http and hasattr(self._local, 'http'):
            return self._local.http

        authorized_http = google_auth_httplib2.AuthorizedHttp(
            self._credentials, http=http_helpers.build_http())

        if self._use_cached_http:
            self._local.http = authorized_http
        return authorized_http

    def _build_request(self, verb, verb_arguments):
        """Builds HttpRequest object.

        Args:
            verb (str): Request verb (ex. insert, update, delete).
            verb_arguments (dict): Arguments to be passed with the request.

        Returns:
            httplib2.HttpRequest: HttpRequest to be sent to the API.
        """
        method = getattr(self._component, verb)

        # Python insists that keys in **kwargs be strings (not variables).
        # Since we initially build our kwargs as a dictionary where one of the
        # keys is a variable (target), we need to convert keys to strings,
        # even though the variable in question is of type str.
        method_args = {str(k): v for k, v in verb_arguments.iteritems()}
        return method(**method_args)

    def _build_next_request(self, verb, prior_request, prior_response):
        """Builds pagination-aware request object.

        More details:
          https://developers.google.com/api-client-library/python/guide/pagination

        Args:
            verb (str): Request verb (ex. insert, update, delete).
            prior_request (httplib2.HttpRequest): Request that may trigger
                paging.
            prior_response (dict): Potentially partial response.

        Returns:
            httplib2.HttpRequest: HttpRequest or None. None is returned when
                there is nothing more to fetch - request completed.
        """
        method = getattr(self._component, verb + '_next')
        return method(prior_request, prior_response)

    def _build_resource_link(self, **kwargs):
        """Build a full URI for a specific resource.

        Args:
            **kwargs: The args to expand in the URI template.

        Returns:
            str: The Resource URI

        Raises:
            ValueError: Raised if the resource_path_template parameter was
                undefined when the repository was created.
        """
        expanded_url = uritemplate.expand(self._resource_path_template, kwargs)
        return urljoin(self.gcp_service._baseUrl, expanded_url)  # pylint: disable=protected-access

    def _request_supports_pagination(self, verb):
        """Determines if the API action supports pagination.

        Args:
            verb (str): Request verb (ex. insert, update, delete).

        Returns:
            bool: True when API supports pagination, False otherwise.
        """
        return getattr(self._component, verb + '_next', None)

    def execute_command(self, verb, verb_arguments):
        """Executes command (ex. add) via a dedicated http object.

        Async APIs may take minutes to complete. Therefore, callers are
        encouraged to leverage concurrent.futures (or similar) to place long
        running commands on a separate threads.

        Args:
            verb (str): Method to execute on the component (ex. get, list).
            verb_arguments (dict): key-value pairs to be passed to
                _build_request.

        Returns:
            dict: An async operation Service Response.
        """
        request = self._build_request(verb, verb_arguments)
        request_submission_status = self._execute(request)
        return request_submission_status

    def execute_paged_query(self, verb, verb_arguments):
        """Executes query (ex. list) via a dedicated http object.

        Args:
            verb (str): Method to execute on the component (ex. get, list).
            verb_arguments (dict): key-value pairs to be passed to
                _BuildRequest.

        Yields:
            dict: Service Response.

        Raises:
            PaginationNotSupportedError: When an API does not support paging.
        """
        if not self._request_supports_pagination(verb=verb):
            raise api_errors.PaginationNotSupportedError(
                '{} does not support pagination')

        request = self._build_request(verb, verb_arguments)

        number_of_pages_processed = 0
        while request is not None:
            response = self._execute(request)
            number_of_pages_processed += 1
            LOGGER.debug('Executing paged request # %s',
                         number_of_pages_processed)
            request = self._build_next_request(verb, request, response)
            yield response

    def execute_search_query(self, verb, verb_arguments):
        """Executes query (ex. search) via a dedicated http object.

        Args:
            verb (str): Method to execute on the component (ex. search).
            verb_arguments (dict): key-value pairs to be passed to
                _BuildRequest.

        Yields:
            dict: Service Response.
        """
        # Implementation of search does not follow the standard API pattern.
        # Fields need to be in the body rather than sent seperately.
        next_page_token = None
        number_of_pages_processed = 0
        while True:
            req_body = verb_arguments.get('body', dict())
            if next_page_token:
                req_body['pageToken'] = next_page_token
            request = self._build_request(verb, verb_arguments)
            response = self._execute(request)
            number_of_pages_processed += 1
            LOGGER.debug('Executing paged request # %s',
                         number_of_pages_processed)
            next_page_token = response.get('nextPageToken')
            yield response

            if not next_page_token:
                break

    def execute_query(self, verb, verb_arguments):
        """Executes query (ex. get) via a dedicated http object.

        Args:
            verb (str): Method to execute on the component (ex. get, list).
            verb_arguments (dict): key-value pairs to be passed to
                _BuildRequest.

        Returns:
            dict: Service Response.
        """
        request = self._build_request(verb, verb_arguments)
        return self._execute(request)

    @replay.replay(REQUEST_REPLAYER)
    @replay.record(REQUEST_RECORDER)
    @retry(retry_on_exception=retryable_exceptions.is_retryable_exception,
           wait_exponential_multiplier=1000, wait_exponential_max=10000,
           stop_max_attempt_number=5)
    def _execute(self, request):
        """Run execute with retries and rate limiting.

        Args:
            request (object): The HttpRequest object to execute.

        Returns:
            dict: The response from the API.
        """
        if self._rate_limiter:
            # Since the ratelimiter library only exposes a context manager
            # interface the code has to be duplicated to handle the case where
            # no rate limiter is defined.
            with self._rate_limiter:
                return request.execute(http=self.http,
                                       num_retries=self._num_retries)
        return request.execute(http=self.http,
                               num_retries=self._num_retries)
# pylint: enable=too-many-instance-attributes, too-many-arguments
# pylint: enable=too-many-locals
