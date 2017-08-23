# Copyright 2017 Google Inc.
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

import logging
import threading

import googleapiclient
from googleapiclient import discovery
import httplib2

from oauth2client.client import GoogleCredentials
from oauth2client.service_account import ServiceAccountCredentials
from ratelimiter import RateLimiter
from retrying import retry

from google.cloud.security.common.gcp_api import _supported_apis
from google.cloud.security.common.gcp_api import errors as api_errors
from google.cloud.security.common.util import log_util
from google.cloud.security.common.util import retryable_exceptions

# Support older versions of apiclient without cache support
SUPPORT_DISCOVERY_CACHE = (googleapiclient.__version__ >= '1.4.2')

# Default value num_retries within HttpRequest execute method
NUM_HTTP_RETRIES = 5

# Per thread storage.
LOCAL_THREAD = threading.local()

LOGGER = log_util.get_logger(__name__)


@retry(retry_on_exception=retryable_exceptions.is_retryable_exception,
       wait_exponential_multiplier=1000, wait_exponential_max=10000,
       stop_max_attempt_number=5)
def _create_service_api(credentials, service_name, version, developer_key=None,
                        cache_discovery=False):
    """Builds and returns a cloud API service object.

    Args:
      credentials (object): GoogleCredentials that will be passed to the
          service.
      service_name (str): The name of the GCE Apiary API.
      version (str): The version of the GCE API to use.
      developer_key (str): The api key to use (for GCE API None is sufficient).
      cache_discovery (bool): Whether or not to cache the discovery doc.

    Returns:
      object: A Resource object with methods for interacting with the service.
    """
    # The default logging of the discovery obj is very noisy in recent versions.
    # Lower the default logging level of just this module to WARNING.
    logging.getLogger(discovery.__name__).setLevel(logging.WARNING)

    discovery_kwargs = {
        'serviceName': service_name,
        'version': version,
        'developerKey': developer_key,
        'credentials': credentials}
    if SUPPORT_DISCOVERY_CACHE:
        discovery_kwargs['cache_discovery'] = cache_discovery

    return discovery.build(**discovery_kwargs)


def credential_from_keyfile(keyfile_name, scopes, delegated_account):
    """Build delegated credentials required for accessing the gsuite APIs.

    Args:
        keyfile_name (str): The filename to load the json service account key
            from.
        scopes (list): The list of required scopes for the service account.
        delegated_account (str): The account to delegate the service account to
            use.

    Returns:
        object: Credentials as built by oauth2client.

    Raises:
        api_errors.ApiExecutionError: If fails to build credentials.
    """
    try:
        credentials = ServiceAccountCredentials.from_json_keyfile_name(
            keyfile_name, scopes=scopes)
    except (ValueError, KeyError, TypeError, IOError) as e:
        raise api_errors.ApiExecutionError(
            'Error building admin api credential: %s', e)

    return credentials.create_delegated(delegated_account)


def flatten_list_results(paged_results, item_key):
    """Flatten a split-up list as returned by list_next() API.

    GCE 'list' APIs return results in the form:
      {item_key: [...]}
    with one dictionary for each "page" of results. This method flattens
    that to a simple list of items.

    Args:
        paged_results (list): A list of paged API response objects.
            [{page 1 results}, {page 2 results}, {page 3 results}, ...]
        item_key (str): The name of the key within the inner "items" lists
            containing the objects of interest.

    Returns:
        list: A list of items.
    """
    results = []
    for page in paged_results:
        results.extend(page.get(item_key, []))
    return results


class BaseRepositoryClient(object):
    """Base class for API repository for a specified Cloud API."""

    def __init__(self,
                 api_name,
                 versions=None,
                 credentials=None,
                 quota_max_calls=None,
                 quota_period=None,
                 use_rate_limiter=False,
                 **kwargs):
        """Constructor.

        Args:
          api_name (str): The API name to wrap. More details here:
                https://developers.google.com/api-client-library/python/apis/
          versions (list): A list of version strings to initialize.
          credentials (object): GoogleCredentials.
          quota_max_calls (int): Allowed requests per <quota_period> for the
              API.
          quota_period (float): The time period to limit the quota_requests to.
          use_rate_limiter (bool): Set to false to disable the use of a rate
              limiter for this service.
          **kwargs (dict): Additional args such as version.
        """
        if not credentials:
            credentials = GoogleCredentials.get_application_default()
        self._credentials = credentials

        # Lock may be acquired multiple times in the same thread.
        self._repository_lock = threading.RLock()

        if use_rate_limiter:
            self._rate_limiter = RateLimiter(max_calls=quota_max_calls,
                                             period=quota_period)
        else:
            self._rate_limiter = None

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

        self.gcp_services = {}
        for version in versions:
            self.gcp_services[version] = _create_service_api(
                self._credentials,
                self.name,
                version,
                kwargs.get('developer_key'),
                kwargs.get('cache_discovery', False))

    def __repr__(self):
        """The object representation.

        Returns:
            str: The object representation.
        """
        return 'API: name=%s, version=%s' % (self.name, self.versions)

    def _init_repository(self, repository_class, gcp_service, repo_property):
        """Safely initialize a repository class to a property.

        Args:
          repository_class (class): The class to initialize.
          gcp_service (object): The gcp service object for the repository.
          repo_property (object): The pointer to the instance of the initialized
              class.

        Returns:
          object: An instance of repository_class.
        """
        with self._repository_lock:
            if not repo_property:  # Verify it still doesn't exist.
                return repository_class(gcp_service, self._credentials,
                                        rate_limiter=self._rate_limiter)

        return repo_property

# pylint: disable=too-many-instance-attributes
class GCPRepository(object):
    """Base class for GCP APIs."""

    def __init__(self, gcp_service, credentials, component, entity='',
                 num_retries=NUM_HTTP_RETRIES, key_field='project',
                 max_results_field='maxResults', rate_limiter=None):
        """Constructor.

        Args:
          gcp_service (object): A Resource object with methods for interacting
              with the service.
          credentials (object): A GoogleCredentials object
          component (str): The subcomponent of the gcp service for this
              repository instance. E.g. 'instances' for compute.instances().*
              APIs
          entity (str): The API entity returned generally by the .get() api.
              E.g. 'instance' for compute.instances().get()
          num_retries (int): The number of http retriable errors to retry on
              before hard failing.
          key_field (str): The field name representing the project to
              query in the API.
          max_results_field (str): The field name that represents the maximum
              number of results to return in one page.
          rate_limiter (object): A RateLimiter object to manage API quota.
        """
        self.gcp_service = gcp_service
        self._credentials = credentials
        components = component.split('.')
        self._component = getattr(
            self.gcp_service, components.pop(0))()
        for nested_component in components:
            self._component = getattr(
                self._component, nested_component)()
        self._entity = entity
        self._num_retries = num_retries
        self._key_field = key_field
        self._max_results_field = max_results_field
        self._rate_limiter = rate_limiter

        self._local = LOCAL_THREAD

    @property
    def http(self):
        """A thread local instance of httplib2.Http.

        Returns:
          object: An httplib2.Http instance authorized by the credentials.
        """
        if hasattr(self._local, 'http'):
            return self._local.http

        self._local.http = httplib2.Http()
        self._credentials.authorize(http=self._local.http)
        return self._local.http

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

        GCP APIs may take minutes to complete. Therefore, callers are
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
          verb_arguments (dict): key-value pairs to be passed to _BuildRequest.

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
            LOGGER.debug('Executing paged request #%s',
                         number_of_pages_processed)
            request = self._build_next_request(verb, request, response)
            yield response

    def execute_search_query(self, verb, verb_arguments):
        """Executes query (ex. search) via a dedicated http object.

        Args:
          verb (str): Method to execute on the component (ex. search).
          verb_arguments (dict): key-value pairs to be passed to _BuildRequest.

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
            LOGGER.debug('Executing paged request #%s',
                         number_of_pages_processed)
            next_page_token = response.get('nextPageToken')
            yield response

            if not next_page_token:
                break

    def execute_query(self, verb, verb_arguments):
        """Executes query (ex. get) via a dedicated http object.

        Args:
          verb (str): Method to execute on the component (ex. get, list).
          verb_arguments (dict): key-value pairs to be passed to _BuildRequest.

        Returns:
          dict: Service Response.
        """
        request = self._build_request(verb, verb_arguments)
        return self._execute(request)

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
        else:
            return request.execute(http=self.http,
                                   num_retries=self._num_retries)
# pylint: enable=too-many-instance-attributes


class ListQueryMixin(object):
    """Mixin that implements Paged List query."""

    def list(self, resource=None, fields=None, max_results=None, verb='list',
             **kwargs):
        """List GCP entities of a given project.

        Args:
          resource (str): The id of the resource to query.
          fields (str): Fields to include in the response - partial response.
          max_results (int): Number of entries to include per page.
          verb (str): The method to call on the API.
          kwargs (dict): Optional additional arguments to pass to the query.

        Yields:
          dict: GCE response.
        """
        assert isinstance(self, GCPRepository)

        arguments = {'fields': fields,
                     self._max_results_field: max_results}

        if self._key_field and resource:
            arguments[self._key_field] = resource

        if kwargs:
            arguments.update(kwargs)

        try:
            for resp in self.execute_paged_query(verb=verb,
                                                 verb_arguments=arguments):
                yield resp
        except api_errors.PaginationNotSupportedError:
            # Some API list() methods are not actually paginated.
            del arguments[self._max_results_field]
            yield self.execute_query(verb=verb, verb_arguments=arguments)


class GetQueryMixin(object):
    """Mixin that implements Get query."""

    def get(self, resource, target=None, fields=None, verb='get', **kwargs):
        """Get GCP entity.

        Args:
          resource (str): The id of the resource to query.
          target (str):  Name of the entity to fetch.
          fields (str): Fields to include in the response - partial response.
          verb (str): The method to call on the API.
          kwargs (dict): Optional additional arguments to pass to the query.

        Returns:
          dict: GCE response.

        Raises:
          errors.HttpError: When attempting to get a non-existent entity.
           ex: HttpError 404 when requesting ... returned
            "The resource '...' was not found"
        """
        assert isinstance(self, GCPRepository)
        assert bool(self._key_field)

        arguments = {self._key_field: resource,
                     'fields': fields}
        if self._entity and target:
            arguments[self._entity] = target
        if kwargs:
            arguments.update(kwargs)

        return self.execute_query(
            verb=verb,
            verb_arguments=arguments,
        )


class GetIamPolicyQueryMixin(object):
    """Mixin that implements getIamPolicy query."""

    def get_iam_policy(self, resource, fields=None, verb='getIamPolicy',
                       include_body=True, resource_field='resource', **kwargs):
        """Get GCP IAM Policy.

        Args:
          resource (str): The id of the resource to fetch.
          fields (str): Fields to include in the response - partial response.
          verb (str): The method to call on the API.
          include_body (bool): If true, include an empty body parameter in the
              method args.
          resource_field (str): The parameter name of the resource field to
              pass to the method.
          kwargs (dict): Optional additional arguments to pass to the query.

        Returns:
          dict: GCE response.

        Raises:
          errors.HttpError: When attempting to get a non-existent entity.
           ex: HttpError 404 when requesting ... returned
            "The resource '...' was not found"
        """
        assert isinstance(self, GCPRepository)

        arguments = {resource_field: resource,
                     'fields': fields}
        if include_body:
            arguments['body'] = {}
        if kwargs:
            arguments.update(kwargs)

        return self.execute_query(
            verb=verb,
            verb_arguments=arguments,
        )
