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
from oauth2client.client import GoogleCredentials
from retrying import retry

from google.cloud.security.common.gcp_api._supported_apis import SUPPORTED_APIS
from google.cloud.security.common.util import retryable_exceptions

# pylint: disable=too-few-public-methods
# TODO: Look into improving to prevent using the disable.
class _BaseClient(object):
    """Base client for a specified GCP API and credentials."""

    def __init__(self, credentials=None, **kwargs):
        if not credentials:
            credentials = GoogleCredentials.get_application_default()
        self._credentials = credentials
        if not kwargs or not kwargs.get('api_name'):
            raise UnsupportedApiError('Unsupported API {}'.format(kwargs))
        self.name = kwargs['api_name']
        if not SUPPORTED_APIS[self.name] or \
            not SUPPORTED_APIS[self.name]['version']:
            raise UnsupportedApiVersionError(
                'Unsupported version {}'.format(SUPPORTED_APIS[self.name]))
        self.version = SUPPORTED_APIS[self.name]['version']
        self.service = discovery.build(self.name, self.version,
                                       credentials=self._credentials)

    def __repr__(self):
        return 'API: name={}, version={}'.format(self.name, self.version)

    # The wait time is (2^X * multiplier) milliseconds, where X is the retry
    # number.
    @retry(retry_on_exception=retryable_exceptions.is_retryable_exception,
           wait_exponential_multiplier=1000, wait_exponential_max=10000,
           stop_max_attempt_number=5)
    # pylint: disable=no-self-use
    # TODO: Investigate if this could be a standalone methods to remove dsiable.
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


# Eventually, move these to the errors module
class Error(Exception):
    """Base Error class."""


class ApiExecutionError(Error):
    """Error for API executions."""

    CUSTOM_ERROR_MESSAGE = 'GCP API Error: unable to get {0} from GCP:\n{1}'


    def __init__(self, resource_name, e):
        super(ApiExecutionError, self).__init__(
            self.CUSTOM_ERROR_MESSAGE.format(resource_name, e))


class UnsupportedApiError(Error):
    """Error for unsupported API."""
    pass


class UnsupportedApiVersionError(Error):
    """Error for unsupported API version."""
    pass
