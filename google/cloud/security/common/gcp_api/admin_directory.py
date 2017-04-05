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

"""Wrapper for Admin Directory  API client."""

from googleapiclient.errors import HttpError
from httplib2 import HttpLib2Error
from oauth2client.contrib.gce import AppAssertionCredentials
from oauth2client.service_account import ServiceAccountCredentials
from ratelimiter import RateLimiter

from google.cloud.security.common.gcp_api import _base_client
from google.cloud.security.common.gcp_api import errors as api_errors
from google.cloud.security.common.util import metadata_server


DEFAULT_MAX_QUERIES = 150000
DEFAULT_RATE_BUCKET_SECONDS = 86400

REQUIRED_SCOPES = frozenset([
    'https://www.googleapis.com/auth/admin.directory.group.readonly'
])


class AdminDirectoryClient(_base_client.BaseClient):
    """GSuite Admin Directory API Client."""

    API_NAME = 'admin'

    def __init__(self, credentials=None, rate_limiter=None):
        super(AdminDirectoryClient, self).__init__(
            credentials=credentials, api_name=self.API_NAME)
        if rate_limiter:
            self.rate_limiter = rate_limiter
        else:
            self.rate_limiter = self.get_rate_limiter()

    @staticmethod
    def get_rate_limiter():
        """Return an appriopriate rate limiter."""
        return RateLimiter(
            DEFAULT_MAX_QUERIES,
            DEFAULT_RATE_BUCKET_SECONDS)

    @staticmethod
    def build_proper_credentials(configs):
        """Build proper credentials required for accessing the directory API.

        Args:
            configs: Dictionary of configurations.

        Returns:
            Credentials as built by oauth2client.

        Raises:
            ApiExecutionError: When an error has occurred executing the API.
        """

        if metadata_server.can_reach_metadata_server():
            return AppAssertionCredentials(REQUIRED_SCOPES)

        try:
            credentials = ServiceAccountCredentials.from_json_keyfile_name(
                configs.get('service_account_credentials_file'),
                scopes=REQUIRED_SCOPES)
        except (ValueError, KeyError, TypeError) as e:
            raise api_errors.ApiExecutionError(
                'Error building admin api credential', e)

        return credentials.create_delegated(
            configs.get('domain_super_admin_email'))

    def get_groups(self, customer_id='my_customer'):
        """Get all the groups for a given customer_id.

        A note on customer_id='my_customer'.
        This is a magic string instead of using the real
        customer id. See:

        https://developers.google.com/admin-sdk/directory/v1/guides/manage-groups#get_all_domain_groups

        Args:
            customer_id: The customer id to scope the request to

        Returns:
            A list of group objects returned from the API.

        Raises:
            ApiExecutionError: When an error has occurred executing the API.
        """
        groups_stub = self.service.groups()
        request = groups_stub.list(customer=customer_id)
        results = []

        # TODO: Investigate yielding results to handle large group lists.
        while request is not None:
            try:
                with self.rate_limiter:
                    response = self._execute(request)
                    results.extend(response.get('groups', []))
                    request = groups_stub.list_next(request, response)
            except (HttpError, HttpLib2Error) as e:
                raise api_errors.ApiExecutionError(groups_stub, e)

        return results
