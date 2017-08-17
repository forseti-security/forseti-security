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

import googleapiclient
from googleapiclient import discovery
from googleapiclient import errors
import httplib2
import json
import logging

from oauth2client.client import GoogleCredentials
from ratelimiter import RateLimiter
from retrying import retry
import threading

from google.cloud.security.common.gcp_api import _supported_apis
from google.cloud.security.common.gcp_api import errors as api_errors
from google.cloud.security.common.util import log_util
from google.cloud.security.common.util import retryable_exceptions

# Support older versions of apiclient without cache support
SUPPORT_DISCOVERY_CACHE = (googleapiclient.__version__ >= '1.4.2')

# Default value num_retries within HttpRequest execute method
NUM_HTTP_RETRIES = 5

LOGGER = log_util.get_logger(__name__)


@retry(retry_on_exception=retryable_exceptions.is_retryable_exception,
       wait_exponential_multiplier=1000, wait_exponential_max=10000,
       stop_max_attempt_number=5)
def _create_service_api(credentials, service_name, version, developer_key=None,
                        cache_discovery=False):
    """Builds and returns a cloud API service object.

    Args:
      credentials: GoogleCredentials that will be passed to the service.
      service_name: The name of the GCE Apiary API.
      version: The version of the GCE API to use.
      developer_key: The api key to use (for GCE API None is sufficient).
      cache_discovery: Whether or not to cache the discovery doc.

    Returns:
      A Resource object with methods for interacting with the service.
    """
    # The default logging of the discovery obj is very noisy in recent versions.
    # Lower the default logging level of just this module to WARNING.
    logging.getLogger(discovery.__name__).setLevel(logging.WARNING)

    discovery_kwargs = {
        'serviceName': service_name,
        'version': version,
        'developerKey': developer_key
        'credentials': credentials}
    if SUPPORT_DISCOVERY_CACHE:
        discovery_kwargs['cache_discovery'] = cache_discovery

    return discovery.build(**discovery_kwargs)


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
          versions ([str]): A list of version strings to initialize.
          credentials: GoogleCredentials.
          quota_max_calls: (int) Allowed requests per <quota_period> for the
              API.
          quota_period: (float) The time period to limit the quota_requests to.
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
            self._rate_limiter = ratelimiter.RateLimiter(
                max_calls=quota_max_calls, period=quota_period)
        else:
            self._rate_limiter = None

        self.name = api_name

        # Look to see if the API is formally supported in Forseti.
        supported_api = _supported_apis.SUPPORTED_APIS.get(api_name)
        if not supported_api:
            LOGGER.warn('API "%s" is not formally supported in Forseti, '
                        'proceed at your own risk.', api_name)

        # See if the version is supported by Forseti.
        # If no version is specified, try to find the supported API's version.
        if not version and supported_api:
            versions = [supported_api.get('version')]
        self.versions = versions

        if supported_api and supported_api.get('version') != version:
            LOGGER.warn('API "%s" version %s is not formally supported '
                        'in Forseti, proceed at your own risk.',
                        api_name, version)

        self.gcp_services = {}
        for version in versions:
          self.gcp_services[version] = _create_service_api(
              self._credentials,
              self.name,
              self.version,
              kwargs.get('developer_key'),
              kwargs.get('cache_discovery', False))

    def __repr__(self):
        """The object representation.

        Returns:
            str: The object representation.
        """
        return 'API: name=%s, version=%s' % (self.name, self.version)

    def _init_repository(self, repository_class, gcp_service, repo_property):
        """Safely initialize a repository class to a property."""
        with self._repository_lock:
            if not repo_property:  # Verify it still doesn't exist.
                repo_property = (
                    _ResourceManagerFoldersRepository(
                        gcp_service, self._credentials,
                        rate_limiter=self._rate_limiter))

        return repo_property


class GCPRepository(object):
    """Base class for GCP APIs."""

    def __init__(
        self,
        gcp_service,
        credentials,
        component,
        entity,
        assert_completion_func=None,
        num_retries=NUM_HTTP_RETRIES,
        rate_limiter=None):
        """Constructor.

        Args:
          gcp_service: A Resource object with methods for interacting with the
              service.
          credentials: A GoogleCredentials object
          component: The subcomponent of the gcp service for this repository
              instance. E.g. 'instances' for compute.instances().* APIs
          entity: The API entity returned generally by the .get() api.
              E.g. 'instance' for compute.instances().get()
          assert_completion_func: A function that watches an async API operation
              and returns when it is complete.
          num_retries: The number of http retriable errors to retry on before
              hard failing.
          rate_limiter: A RateLimiter object to manage API quota.
        """
        self.gcp_service = gcp_service
        self._credentials = credentials
        self._component = getattr(self.gcp_service, component)()
        self._entity = entity
        self._assert_completion_func = assert_completion_func
        self._num_retries = num_retries
        self._rate_limiter = rate_limiter

        self._local = LOCAL_THREAD

    @property
    def http(self):
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
          dict: Service Response.
        """
        request = self._build_request(verb, verb_arguments)
        # It appears that all API calls include project as part of their
        # signature. Leveraging this fact to extract the name of project -
        # instead of trying to parse it out from the response, where json
        # schema is subject to change.
        project = verb_arguments['project']

        request_submission_status = self._execute(request)

        if self._assert_completion_func is not None:
            return self._assert_completion_func(request_submission_status,
                                                project)

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
        """Run execute with retries and rate limiting."""
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


class ListQueryMixin(object):
  """Mixin that implements Paged List query."""

    def list(self, project, fields=None, max_results=None, verb='list',
             **kwargs):
        """List GCP entities of a given project.

        Args:
          project: The id of the project to query.
          fields ([str]): Fields to include in the response - partial response.
          max_results (int): Number of entries to include per page.
          verb (str): The method to call on the API.
          kwargs (dict): Optional additional arguments to pass to the query.

        Yields:
          dict: GCE response.
        """
        assert isinstance(self, GCPRepository)

        arguments = {'project': project,
                     'fields': fields,
                     'maxResults': max_results}

        if kwargs:
            arguments.update(kwargs)

        for resp in self.execute_paged_query(
            verb='list',
            verb_arguments=arguments):
            yield resp


class GetQueryMixin(object):
    """Mixin that implements Get query."""

    def get(self, project, target, fields=None, verb='get', **kwargs):
        """Get GCP entity.

        Args:
          project (str): The id of the project to modify.
          target (str):  Name of the entity to fetch.
          fields ([str]): Fields to include in the response - partial response.
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

        arguments = {'project': project,
                     self._entity: target,
                     'fields': fields}
        if kwargs:
            arguments.update(kwargs)

        return self.execute_query(
            verb=verb,
            verb_arguments=arguments,
        )

class GetIamPolicyQueryMixin(object):
    """Mixin that implements Get query."""

    def get_iam_policy(self, resource, fields=None, verb='getIamPolicy',
                       **kwargs):
        """Get GCP entity.

        Args:
          project (str): The id of the project to modify.
          target (str):  Name of the entity to fetch.
          fields ([str]): Fields to include in the response - partial response.
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

        arguments = {'resource': resource,
                     'fields': fields}
        if kwargs:
            arguments.update(kwargs)

        return self.execute_query(
            verb=verb,
            verb_arguments=arguments,
        )
