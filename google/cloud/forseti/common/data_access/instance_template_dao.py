# Copyright 2017 The Forseti Security Authors. All rights reserved.
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

"""Data access object for InstanceTemplate."""

from google.cloud.forseti.common.data_access import dao
from google.cloud.forseti.common.data_access.sql_queries import select_data
from google.cloud.forseti.common.gcp_type import instance_template
from google.cloud.forseti.common.gcp_type import resource
from google.cloud.forseti.common.util import log_util


LOGGER = log_util.get_logger(__name__)


class InstanceTemplateDao(dao.Dao):
    """InstanceTemplate DAO."""

    def get_instance_templates(self, timestamp):
        """Get instance templates from a particular snapshot.

        Args:
            timestamp (str): The snapshot timestamp.

        Returns:
            list: A list of InstanceTemplate.

        Raises:
            MySQLError: If a MySQL error occurs.
        """
        query = select_data.INSTANCE_TEMPLATES.format(timestamp)
        rows = self.execute_sql_with_fetch(
            resource.ResourceType.INSTANCE_TEMPLATE, query, ())
        return [self.map_row_to_object(instance_template.InstanceTemplate, row)
                for row in rows]
