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

"""Data access object for BackendService."""

from google.cloud.security.common.data_access import dao
from google.cloud.security.common.data_access.sql_queries import select_data
from google.cloud.security.common.gcp_type import backend_service as bs
from google.cloud.security.common.gcp_type import resource
from google.cloud.security.common.util import log_util

LOGGER = log_util.get_logger(__name__)


class BackendServiceDao(dao.Dao):
    """BackendService DAO."""

    def get_backend_services(self, timestamp):
        """Get backend services from a particular snapshot.

        Args:
            timestamp: The snapshot timestamp.

        Returns:
            A list of BackendService.

        Raises:
            MySQLError if a MySQL error occurs.
        """
        query = select_data.BACKEND_SERVICES.format(timestamp)
        rows = self.execute_sql_with_fetch(
            resource.ResourceType.BACKEND_SERVICE, query, ())
        return [self.map_row_to_object(bs.BackendService, row) for row in rows]
