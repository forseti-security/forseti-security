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

"""Wrapper for the BigQuery API client."""

import gflags as flags
from googleapiclient.errors import HttpError
from httplib2 import HttpLib2Error
from ratelimiter import RateLimiter

from google.cloud.security.common.gcp_api import _base_client
from google.cloud.security.common.gcp_api import errors as api_errors
from google.cloud.security.common.util import log_util

FLAGS = flags.FLAGS

flags.DEFINE_integer('max_bigquery_api_calls_per_100_seconds', 17000,
                     'BigQuery Discovery requests per 100 seconds.')

LOGGER = log_util.get_logger(__name__)


class BigQueryClient(_base_client.BaseClient):
    """BigQuery Client."""

    API_NAME = 'bigquery'
    DEFAULT_QUOTA_TIMESPAN_PER_SECONDS = 100

    def __init__(self):
        super(BigQueryClient, self).__init__(
            api_name=self.API_NAME)
        self.rate_limiter = self.get_rate_limiter()
        
    def get_rate_limiter(self):
        """Return an appropriate rate limiter."""
        return RateLimiter(FLAGS.max_bigquery_api_calls_per_100_seconds,
                           self.DEFAULT_QUOTA_TIMESPAN_PER_SECONDS)
    
    def get_datasets(self, project_id):
        """Return BigQuery datasets stored in the requested project_id.
        
        Args:
            project_id: A String representing the unique project_id.
            
        Returns:
        """
        bigquery_stub = self.service.datasets()
        request = bigquery_stub.list(projectId=project_id, all=True)
        results = []

        # TODO: Investigate yielding results to handle large group lists.
        while request is not None:
            try:
                with self.rate_limiter:
                    response = self._execute(request)
                    results.extend(response.get('datasets', []))
                    request = bigquery_stub.list_next(request, response)
            except (HttpError, HttpLib2Error) as e:
                raise api_errors.ApiExecutionError(bigquery_stub, e)

        return results
      