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
from ratelimiter import RateLimiter

from google.cloud.security.common.gcp_api._base_client import _BaseClient
from google.cloud.security.common.gcp_api._base_client import ApiExecutionError
from google.cloud.security.common.util.log_util import LogUtil


LOGGER = LogUtil.setup_logging(__name__)


class AdminDirectoryClient(_BaseClient):
    """GSuite Admin Directory API Client."""

    API_NAME = 'admin'

    def __init__(self, credentials=None, rate_limiter=None):
        super(AdminDirectoryClient, self).__init__(
            credentials=credentials, api_name=self.API_NAME)
        if rate_limiter:
            self.rate_limiter = rate_limiter
        else:
            self.rate_limiter = get_rate_limiter()

    @staticmethod
    def get_rate_limiter():
        DEFAULT_MAX_QUERIES = 150000
        DEFAULT_RATE_BUCKET_SECONDS = 86400

        return RateLimiter(
            DEFAULT_DAILY_MAX_QUERIES,
            DEFAULT_RATE_BUCKET_SECONDS)

    def get_groups(self, customer_id='my_customer'):
        """Get all the groups for a given customer_id.

        A note on customer_id='my_customer'. This is a magic string instead
        of using the real customer id.

        See: https://developers.google.com/admin-sdk/directory/v1/guides/manage-groups#get_all_domain_groups

        Args:
            customer_id: The customer id to scope the request to

        Returns:
            A list of group objects returned from the API.

        Raises:
            ApiExecutionError: When an error has occured executing the API.
        """
        groups_stub = self.service.groups()
        request = groups_stub.list(customer=customer_id)
        results = []

        while request is not None:
            try:
                with self.rate_limiter:
                    response = self._execute(request)
                    results.extend(response.get('groups', []))
                    request = groups_stub.list_next(request, response)
            except (HttpError, HttpLib2Error) as e:
                raise ApiExecutionError(groups_stub, e)

        return results
