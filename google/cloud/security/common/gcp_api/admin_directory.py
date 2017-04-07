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
from googleapiclient.errors import HttpError
from httplib2 import HttpLib2Error
from oauth2client.contrib.gce import AppAssertionCredentials
from oauth2client.service_account import ServiceAccountCredentials
from ratelimiter import RateLimiter

from google.cloud.security.common.gcp_api import _base_client
from google.cloud.security.common.gcp_api import errors as api_errors
from google.cloud.security.common.util import metadata_server

FLAGS = flags.FLAGS

flags.DEFINE_string('domain_super_admin_email', None,
                    'An email address of a super-admin in the GSuite domain.')

flags.DEFINE_string('service_account_email', None,
                    'The email of the service account.')

flags.DEFINE_string('service_account_credentials_file', None,
                    'The file with credentials for the service account.'
                    'NOTE: This is only required when running locally.')

flags.DEFINE_integer('max_admin_api_calls_per_day', 150000,
                     'Admin SDK queries per day.')


class AdminDirectoryClient(_base_client.BaseClient):
    """GSuite Admin Directory API Client."""

    API_NAME = 'admin'
    DEFAULT_QUOTA_TIMESPAN_PER_SECONDS = 86400  #pylint: enable=invalid-name

    REQUIRED_SCOPES = frozenset([
        'https://www.googleapis.com/auth/admin.directory.group.readonly'
    ])

    def __init__(self):
        super(AdminDirectoryClient, self).__init__(
            credentials=self._build_proper_credentials(),
            api_name=self.API_NAME)
        self.rate_limiter = RateLimiter(
            FLAGS.max_admin_api_calls_per_day,
            self.DEFAULT_QUOTA_TIMESPAN_PER_SECONDS)

    def _build_proper_credentials(self):
        """Build proper credentials required for accessing the directory API.

        Returns:
            Credentials as built by oauth2client.

        Raises:
            ApiExecutionError: When an error has occurred executing the API.
        """

        if metadata_server.can_reach_metadata_server():
            return AppAssertionCredentials(self.REQUIRED_SCOPES)

        try:
            credentials = ServiceAccountCredentials.from_json_keyfile_name(
                FLAGS.service_account_credentials_file,
                scopes=self.REQUIRED_SCOPES)
        except (ValueError, KeyError, TypeError) as e:
            raise api_errors.ApiExecutionError(
                'Error building admin api credential:\n%s', e)

        return credentials.create_delegated(
            FLAGS.domain_super_admin_email)

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
