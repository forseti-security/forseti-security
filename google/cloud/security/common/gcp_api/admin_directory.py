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

import glfags as flags

from googleapiclient.errors import HttpError
from httplib2 import HttpLib2Error
from oauth2client.service_account import ServiceAccountCredentials
from ratelimiter import RateLimiter

from google.cloud.security.common.gcp_api import _base_client
from google.cloud.security.common.gcp_api import errors as api_errors


FLAGS = flags.FLAGS

DEFAULT_MAX_QUERIES = 150000
DEFAULT_RATE_BUCKET_SECONDS = 86400

REQUIRED_SCOPES = frozenset([
    'https://www.googleapis.com/auth/admin.directory.group.readonly'
])

flags.DEFINE_string('domain_super_admin_email', None,
                    'An email address of a super-admin in the GSuite domain. '
                    'REQUIRED: if inventory_groups is enabled.')
flags.DEFINE_string('groups_service_account_email', None,
                    'The email of the service account. '
                    'REQUIRED: if inventory_groups is enabled.')
flags.DEFINE_string('groups_service_account_key_file', None,
                    'The key file with credentials for the service account. '
                    'REQUIRED: If inventory_groups is enabled and '
                    'runnning locally.')

class AdminDirectoryClient(_base_client.BaseClient):
    """GSuite Admin Directory API Client."""

    API_NAME = 'admin'

    def __init__(self, configs, credentials=None, rate_limiter=None):
        super(AdminDirectoryClient, self).__init__(
            credentials=credentials, api_name=self.API_NAME)

        if rate_limiter:
            self.rate_limiter = rate_limiter
        else:
            self.rate_limiter = self.get_rate_limiter()

        if credentials:
            self.credentials = credentials
        else:
            self.credentials = self._build_credentials()

        self.configs = configs

    def _build_credentials(self):
        """Build credentials required for accessing the directory API.

        Returns:
            Credentials as built by oauth2client.

        Raises:
            api_errors.ApiExecutionError
        """
        try:
            credentials = ServiceAccountCredentials.from_json_keyfile_name(
                self.configs.get('groups_service_account_key_file'),
                scopes=REQUIRED_SCOPES)
        except (ValueError, KeyError, TypeError) as e:
            raise api_errors.ApiExecutionError(
                'Error building admin api credential: %s', e)

        return credentials.create_delegated(
            self.configs.get('domain_super_admin_email'))

    @staticmethod
    def get_rate_limiter():
        """Return an appriopriate rate limiter."""
        return RateLimiter(
            DEFAULT_MAX_QUERIES,
            DEFAULT_RATE_BUCKET_SECONDS)

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
            api_errors.ApiExecutionError
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
