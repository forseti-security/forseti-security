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

from apiclient import discovery
from googleapiclient.errors import HttpError
from httplib2 import HttpLib2Error
from oauth2client.client import GoogleCredentials
from retrying import retry

from google.cloud.security.common.gcp_api import _supported_apis
from google.cloud.security.common.gcp_api import errors as api_errors
from google.cloud.security.common.util import retryable_exceptions

# pylint: disable=too-few-public-methods
class BaseClient(object):
    """Base client for a specified GCP API and credentials."""

    def __init__(self, credentials=None, **kwargs):
        if not credentials:
            credentials = GoogleCredentials.get_application_default()
        self._credentials = credentials
        if not kwargs or not kwargs.get('api_name'):
            raise api_errors.UnsupportedApiError(
                'Unsupported API {}'.format(kwargs))
        self.name = kwargs['api_name']
        if not _supported_apis.SUPPORTED_APIS[self.name] or \
            not _supported_apis.SUPPORTED_APIS[self.name]['version']:
            raise api_errors.UnsupportedApiVersionError(
                'Unsupported version {}'.format(
                    _supported_apis.SUPPORTED_APIS[self.name]))
        self.version = _supported_apis.SUPPORTED_APIS[self.name]['version']
        self.service = discovery.build(self.name, self.version,
                                       credentials=self._credentials,
                                       cache_discovery=False)

    def __repr__(self):
        return 'API: name=%s, version=%s' % (self.name, self.version)

    # The wait time is (2^X * multiplier) milliseconds, where X is the retry
    # number.
    @retry(retry_on_exception=retryable_exceptions.is_retryable_exception,
           wait_exponential_multiplier=1000, wait_exponential_max=10000,
           stop_max_attempt_number=5)
    # pylint: disable=no-self-use
    # TODO: Investigate if this could be a standalone methods to remove disable.
    def _execute(self, request):
        """Executes requests in a rate-limited way.

        Args:
            request: GCP API client request object.

        Returns:
            API response object.

        Raises:
            When the retry is exceeded, exception will be thrown.  This
            exception is not wrapped by the retry library, and will be handled
            upstream.
        """
        return request.execute()

    def _build_paged_result(self, request, api_stub, rate_limiter):
        """Execute results and page through the results.

        Args:
            request: GCP API client request object.
            api_stub: The API stub used to build the request.
            rate_limiter: An instance of RateLimiter to use.

        Returns:
            API response object.

        Raises:
            When the retry is exceeded, exception will be thrown.  This
            exception is not wrapped by the retry library, and will be handled
            upstream.
        """
        results = []
        while request is not None:
            try:
                with rate_limiter:
                    response = self._execute(request)
                    results.append(response)
                    request = api_stub.list_next(request, response)
            except (HttpError, HttpLib2Error) as e:
                raise api_errors.ApiExecutionError(api_stub, e)

        return results
