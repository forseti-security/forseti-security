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
import logging
import threading
import googleapiclient
from googleapiclient import discovery
import httplib2
from oauth2client import client
from oauth2client import service_account
from ratelimiter import RateLimiter
from retrying import retry

from google.cloud import security as forseti_security
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
        credentials (OAuth2Credentials): Credentials that will be used to
            authenticate the API calls.
        service_name (str): The name of the API.
        version (str): The version of the API to use.
        developer_key (str): The api key to use, .
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


def _set_user_agent(credentials):
    """Set custom Forseti user agent for all authenticated requests.

    Args:
        credentials (OAuth2Credentials): The credentials object used to
            authenticate all http requests.
    """
    if isinstance(credentials, client.OAuth2Credentials):
        user_agent = credentials.user_agent
        if (not user_agent or
                forseti_security.__package_name__ not in user_agent):

            credentials.user_agent = (
                'Python-httplib2/{} (gzip), {}/{}'.format(
                    httplib2.__version__,
                    forseti_security.__package_name__,
                    forseti_security.__version__))


def credential_from_keyfile(keyfile_name, scopes, delegated_account):
    """Build delegated credentials required for accessing the gsuite APIs.

    Args:
        keyfile_name (str): The filename to load the json service account key
            from.
        scopes (list): The list of required scopes for the service account.
        delegated_account (str): The account to delegate the service account to
            use.

    Returns:
        OAuth2Credentials: Credentials as built by oauth2client.

    Raises:
        api_errors.ApiExecutionError: If fails to build credentials.
    """
    try:
        credentials = (
            service_account.ServiceAccountCredentials.from_json_keyfile_name(
                keyfile_name, scopes=scopes))
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


def flatten_aggregated_list_results(paged_results, item_key):
    """Flatten a split-up list as returned by GCE "aggregatedList" API.

    The compute API's aggregatedList methods return a structure in
    the form:
      {
        items: {
          $group_value_1: {
            $item_key: [$items]
          },
          $group_value_2: {
            $item_key: [$items]
          },
          $group_value_3: {
            "warning": {
              message: "There are no results for ..."
            }
          },
          ...,
          $group_value_n, {
            $item_key: [$items]
          },
        }
      }
    where each "$group_value_n" is a particular element in the
    aggregation, e.g. a particular zone or group or whatever, and
    "$item_key" is some type-specific resource name, e.g.
    "backendServices" for an aggregated list of backend services.

    This method takes such a structure and yields a simple list of
    all $items across all of the groups.

    Args:
        paged_results (list): A list of paged API response objects.
            [{page 1 results}, {page 2 results}, {page 3 results}, ...]
        item_key (str): The name of the key within the inner "items" lists
            containing the objects of interest.

    Returns:
        list: A list of items.
    """
    items = []
    for page in paged_results:
        aggregated_items = page.get('items', {})
        for items_for_grouping in aggregated_items.values():
            for item in items_for_grouping.get(item_key, []):
                items.append(item)
    return items


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
            quota_period (float): The time period to track requests over.
            use_rate_limiter (bool): Set to false to disable the use of a rate
                limiter for this service.
            **kwargs (dict): Additional args such as version.
        """
        if not credentials:
            credentials = client.GoogleCredentials.get_application_default()
        self._credentials = credentials

        _set_user_agent(credentials)

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
                                    rate_limiter=self._rate_limiter)


# pylint: disable=too-many-instance-attributes, too-many-arguments
class GCPRepository(object):
    """Base class for GCP APIs."""

    def __init__(self, gcp_service, credentials, component,
                 num_retries=NUM_HTTP_RETRIES, key_field='project',
                 entity_field=None, list_key_field=None, get_key_field=None,
                 max_results_field='maxResults', search_query_field='query',
                 rate_limiter=None):
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
        self._rate_limiter = rate_limiter

        self._local = LOCAL_THREAD

    @property
    def http(self):
        """A thread local instance of httplib2.Http.

        Returns:
            httplib2.Http: An Http instance authorized by the credentials.
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
            LOGGER.debug('Executing paged request #%s',
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
            verb_arguments (dict): key-value pairs to be passed to
                _BuildRequest.

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
# pylint: enable=too-many-instance-attributes, too-many-arguments


class ListQueryMixin(object):
    """Mixin that implements Paged List query."""

    def list(self, resource=None, fields=None, max_results=None, verb='list',
             **kwargs):
        """List subresources of a given resource.

        Args:
            self (GCPRespository): An instance of a GCPRespository class.
            resource (str): The id of the resource to query.
            fields (str): Fields to include in the response - partial response.
            max_results (int): Number of entries to include per page.
            verb (str): The method to call on the API.
            **kwargs (dict): Optional additional arguments to pass to the query.

        Yields:
            dict: An API response containing one page of results.
        """
        arguments = {'fields': fields,
                     self._max_results_field: max_results}

        # Most APIs call list on a parent resource to list subresources of
        # a specific type. For APIs that have no parent, set the list_key_field
        # to None when initializing the GCPRespository instance.
        if self._list_key_field and resource:
            arguments[self._list_key_field] = resource

        if kwargs:
            arguments.update(kwargs)

        if self._request_supports_pagination(verb):
            for resp in self.execute_paged_query(verb=verb,
                                                 verb_arguments=arguments):
                yield resp
        else:
            # Some API list() methods are not actually paginated.
            del arguments[self._max_results_field]
            yield self.execute_query(verb=verb, verb_arguments=arguments)


class AggregatedListQueryMixin(ListQueryMixin):
    """Mixin that implements a Paged List and AggregatedList query."""

    def aggregated_list(self, resource=None, fields=None, max_results=None,
                        verb='aggregatedList', **kwargs):
        """List all subresource entities of a given resource.

        Args:
            self (GCPRespository): An instance of a GCPRespository class.
            resource (str): The id of the resource to query.
            fields (str): Fields to include in the response - partial response.
            max_results (int): Number of entries to include per page.
            verb (str): The method to call on the API.
            **kwargs (dict): Optional additional arguments to pass to the query.

        Returns:
            iterator: An iterator of API responses by page.
        """
        return super(AggregatedListQueryMixin, self).list(
            resource, fields, max_results, verb, **kwargs)


class GetQueryMixin(object):
    """Mixin that implements Get query."""

    def get(self, resource, target=None, fields=None, verb='get', **kwargs):
        """Get API entity.

        Args:
            self (GCPRespository): An instance of a GCPRespository class.
            resource (str): The id of the resource to query.
            target (str):  Name of the entity to fetch.
            fields (str): Fields to include in the response - partial response.
            verb (str): The method to call on the API.
            **kwargs (dict): Optional additional arguments to pass to the query.

        Returns:
            dict: GCE response.

        Raises:
            ValueError: When get_key_field was not defined in the base
                GCPRepository instance.

            errors.HttpError: When attempting to get a non-existent entity.
               ex: HttpError 404 when requesting ... returned
                   "The resource '...' was not found"
        """
        if not self._get_key_field:
            raise ValueError('Repository was created without a valid '
                             'get_key_field argument. Cannot execute get '
                             'request.')

        arguments = {self._get_key_field: resource,
                     'fields': fields}

        # Most APIs take both a resource and a target when calling get, but
        # for APIs that the resource itself is the target, then setting
        # 'entity' to None when initializing the GCPRepository instance will
        # ensure the correct parameters are passed to the API method.
        if self._entity_field and target:
            arguments[self._entity_field] = target
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
        """Get resource IAM Policy.

        Args:
            self (GCPRespository): An instance of a GCPRespository class.
            resource (str): The id of the resource to fetch.
            fields (str): Fields to include in the response - partial response.
            verb (str): The method to call on the API.
            include_body (bool): If true, include an empty body parameter in the
                method args.
            resource_field (str): The parameter name of the resource field to
                pass to the method.
            **kwargs (dict): Optional additional arguments to pass to the query.

        Returns:
            dict: GCE response.

        Raises:
            errors.HttpError: When attempting to get a non-existent entity.
                ex: HttpError 404 when requesting ... returned
                    "The resource '...' was not found"
        """
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


class SearchQueryMixin(object):
    """Mixin that implements Search query."""

    def search(self, query=None, fields=None, max_results=500, verb='search'):
        """List all subresource entities visable to the caller.

        Args:
            self (GCPRespository): An instance of a GCPRespository class.
            query (str): Additional filters to apply to the restrict the
                set of resources returned.
            fields (str): Fields to include in the response - partial response.
            max_results (int): Number of entries to include per page.
            verb (str): The method to call on the API.

        Yields:
            dict: Response from the API.
        """
        req_body = {}
        if query:
            req_body[self._search_query_field] = query

        req_body[self._max_results_field] = max_results

        for resp in self.execute_search_query(
                verb=verb,
                verb_arguments={'body': req_body, 'fields': fields}):
            yield resp
