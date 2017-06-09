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

import gflags as flags

from oauth2client.service_account import ServiceAccountCredentials
from ratelimiter import RateLimiter

from google.cloud.security.common.gcp_api import _base_client
from google.cloud.security.common.gcp_api import errors as api_errors


FLAGS = flags.FLAGS


class AdminDirectoryClient(_base_client.BaseClient):
    """GSuite Admin Directory API Client."""

    API_NAME = 'admin'
    DEFAULT_QUOTA_TIMESPAN_PER_SECONDS = 86400 # pylint: disable=invalid-name
    REQUIRED_SCOPES = frozenset([
        'https://www.googleapis.com/auth/admin.directory.group.readonly'
    ])

    def __init__(self):
        super(AdminDirectoryClient, self).__init__(
            credentials=self._build_credentials(),
            api_name=self.API_NAME)

        self.rate_limiter = RateLimiter(
            FLAGS.max_admin_api_calls_per_day,
            self.DEFAULT_QUOTA_TIMESPAN_PER_SECONDS)

    def _build_credentials(self):
        """Build credentials required for accessing the directory API.

        Returns:
            Credentials as built by oauth2client.

        Raises:
            api_errors.ApiExecutionError
        """
        try:
            credentials = ServiceAccountCredentials.from_json_keyfile_name(
                FLAGS.groups_service_account_key_file,
                scopes=self.REQUIRED_SCOPES)
        except (ValueError, KeyError, TypeError) as e:
            raise api_errors.ApiExecutionError(
                'Error building admin api credential: %s', e)

        return credentials.create_delegated(
            FLAGS.domain_super_admin_email)

    def get_rate_limiter(self):
        """Return an appriopriate rate limiter."""
        return RateLimiter(FLAGS.max_admin_api_calls_per_day,
                           self.DEFAULT_QUOTA_TIMESPAN_PER_SECONDS)

    def get_group_members(self, group_key):
        """Get all the members for specified groups.

        Args:
            group_key: Its unique id assigned by the Admin API.

        Returns:
            A list of member objects from the API.

        Raises:
            api_errors.ApiExecutionError
        """
        members_api = self.service.members()
        request = members_api.list(groupKey=group_key,
                                   maxResults=FLAGS.max_results_admin_api)

        paged_results = self._build_paged_result(
            request, members_api, self.rate_limiter)

        return self._flatten_list_results(paged_results, 'members')

    def get_groups(self, customer_id='my_customer'):
        """Get all the groups for a given customer_id.

        A note on customer_id='my_customer'. This is a magic string instead
        of using the real customer id. See:

        https://developers.google.com/admin-sdk/directory/v1/guides/manage-groups#get_all_domain_groups

        Args:
            customer_id: The customer id to scope the request to

        Returns:
            A list of group objects returned from the API.

        Raises:
            api_errors.ApiExecutionError
        """
        groups_api = self.service.groups()
        request = groups_api.list(customer=customer_id)

        paged_results = self._build_paged_result(
            request, groups_api, self.rate_limiter)

        return self._flatten_list_results(paged_results, 'groups')
