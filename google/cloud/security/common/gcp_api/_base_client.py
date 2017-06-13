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

import json
import httplib2

from apiclient import discovery
from googleapiclient.errors import HttpError
from oauth2client.client import GoogleCredentials
from retrying import retry

from google.cloud import security as forseti_security
from google.cloud.security.common.gcp_api import _supported_apis
from google.cloud.security.common.gcp_api import errors as api_errors
from google.cloud.security.common.util import log_util
from google.cloud.security.common.util import retryable_exceptions

LOGGER = log_util.get_logger(__name__)


def _attach_user_agent(request):
    """Append our UA to the headers of an googelapiclient request object.

        Args:
            request: A googlapiclient request object

        Returns:
            A modified googleapiclient request object.
    """
    user_agent = request.headers['user-agent']
    request.headers['user-agent'] = user_agent + ', %s/%s ' % (
        forseti_security.__package_name__,
        forseti_security.__version__)

    return request


# pylint: disable=too-few-public-methods
class BaseClient(object):
    """Base client for a specified GCP API and credentials."""
    def __init__(self, credentials=None, api_name=None, **kwargs):
        """Thin client wrapper over the Google Discovery API.

        The intent for this class is to define the Google APIs expected by
        Forseti. While other APIs and versions can be specified, it may not
        be stable and could cause unknown issues in Forseti.

        Args:
            credentials: Google credentials for auth-ing to the API.
            api_name: The API name to wrap. More details here:
                https://developers.google.com/api-client-library/python/apis/
            kwargs: Additional args such as version.
        """
        if not credentials:
            credentials = GoogleCredentials.get_application_default()
        self._credentials = credentials

        self.name = api_name

        # Look to see if the API is formally supported in Forseti.
        supported_api = _supported_apis.SUPPORTED_APIS.get(api_name)
        if not supported_api:
            LOGGER.warn('API "%s" is not formally supported in Forseti, '
                        'proceed at your own risk.', api_name)

        # See if the version is supported by Forseti.
        # If no version is specified, try to find the supported API's version.
        version = kwargs.get('version')
        if not version and supported_api:
            version = supported_api.get('version')
        self.version = version

        if supported_api and supported_api.get('version') != version:
            LOGGER.warn('API "%s" version %s is not formally supported '
                        'in Forseti, proceed at your own risk.',
                        api_name, version)

        should_cache_discovery = kwargs.get('cache_discovery')

        self.service = discovery.build(self.name,
                                       self.version,
                                       credentials=self._credentials,
                                       cache_discovery=should_cache_discovery)

    def __repr__(self):
        return 'API: name=%s, version=%s' % (self.name, self.version)

    @staticmethod
    # The wait time is (2^X * multiplier) milliseconds, where X is the retry
    # number.
    @retry(retry_on_exception=retryable_exceptions.is_retryable_exception,
           wait_exponential_multiplier=1000, wait_exponential_max=10000,
           stop_max_attempt_number=5)
    def _execute(request, rate_limiter=None):
        """Executes requests in a rate-limited way.

        Args:
            request: GCP API client request object.
            rate_limiter: An instance of RateLimiter to use.  Will be None
                for api without any rate limits.

        Returns:
            API response object.

        Raises:
            When the retry is exceeded, exception will be thrown.  This
            exception is not wrapped by the retry library, and will be handled
            upstream.
        """
        request = _attach_user_agent(request)
        try:
            if rate_limiter is not None:
                with rate_limiter:
                    return request.execute()
            return request.execute()
        except HttpError as e:
            if (e.resp.status == 403 and
                    e.resp.get('content-type', '').startswith(
                        'application/json')):

                # If a project doesn't have the necessary API enabled, Google
                # will return an error domain=usageLimits and
                # reason=accessNotConfigured. Clients may wish to handle this
                # error in some particular way. For instance, when listing
                # resources, it might be treated as "no resources of that type
                # are present", if the API would need to be enabled in order
                # to create the resources in question!
                #
                # So, if we find that specific error, raise a different
                # exception to indicate it to callers. Otherwise, propagate
                # the initial exception.
                error_details = json.loads(e.content)
                errors = error_details.get('error', {}).get('errors', [])
                api_disabled_errors = [
                    error for error in errors
                    if (error.get('domain') == 'usageLimits'
                        and error.get('reason') == 'accessNotConfigured')]
                if (api_disabled_errors and
                        len(api_disabled_errors) == len(errors)):
                    raise api_errors.ApiNotEnabledError(
                        api_disabled_errors[0].get('extendedHelp', ''),
                        e)
            raise

    def _build_paged_result(self, request, api_stub, rate_limiter,
                            next_stub=None):
        """Execute results and page through the results.

        Use of this method requires the API having a .list_next() method.

        Args:
            request: GCP API client request object.
            api_stub: The API stub used to build the request.
            rate_limiter: An instance of RateLimiter to use.  Will be None
                for api without any rate limits.
            next_stub: The API stub used to get the next page of results.

        Returns:
            A list of paged API response objects.
            [{page 1 results}, {page 2 results}, {page 3 results}, ...]

        Raises:
            api_errors.ApiExecutionError when there is no list_next() method
            on the api_stub.
        """
        if next_stub is None:
            if not hasattr(api_stub, 'list_next'):
                raise api_errors.ApiExecutionError(
                    api_stub, 'No list_next() method.')
            next_stub = api_stub.list_next

        results = []

        while request is not None:
            try:
                response = self._execute(request, rate_limiter)
                results.append(response)
                request = next_stub(request, response)
            except api_errors.ApiNotEnabledError:
                # If the API isn't enabled on the resource, there must
                # not be any resources. So, just swallow the error:
                # we're done!
                break
            except (HttpError, httplib2.HttpLib2Error) as e:
                raise api_errors.ApiExecutionError(api_stub, e)

        return results

    @staticmethod
    # pylint: disable=invalid-name
    def _flatten_aggregated_list_results(paged_results, item_key):
    # pylint: enable=invalid-name
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
        page_results : A list of paged API response objects.
            [{page 1 results}, {page 2 results}, {page 3 results}, ...]
        item_key: The name of the key within the inner "items" lists
            containing the objects of interest.

        Return:
          A list of items.
        """
        items = []
        for page in paged_results:
            aggregated_items = page.get('items', {})
            for items_for_grouping in aggregated_items.values():
                for item in items_for_grouping.get(item_key, []):
                    items.append(item)
        return items

    @staticmethod
    # pylint: disable=invalid-name
    def _flatten_list_results(paged_results, item_key):
    # pylint: enable=invalid-name
        """Flatten a split-up list as returned by list_next() API.

        GCE 'list' APIs return results in the form:
          {item_key: [...]}
        with one dictionary for each "page" of results. This method flattens
        that to a simple list of items.

        Args:
            paged_results : A list of paged API response objects.
                [{page 1 results}, {page 2 results}, {page 3 results}, ...]
            item_key: The name of the key within the inner "items" lists
                containing the objects of interest.

        Return:
            A list of GCE resources.
        """
        results = []
        for page in paged_results:
            results.extend(page.get(item_key, []))
        return results
