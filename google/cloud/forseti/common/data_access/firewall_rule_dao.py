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

"""Data access object for FirewallRule."""

from google.cloud.forseti.common.data_access import dao
from google.cloud.forseti.common.data_access.sql_queries import select_data
from google.cloud.forseti.common.gcp_type import firewall_rule
from google.cloud.forseti.common.gcp_type import resource
from google.cloud.forseti.common.util import log_util

LOGGER = log_util.get_logger(__name__)


class FirewallRuleDao(dao.Dao):
    """Firewall rule DAO."""

    def get_firewall_rules(self, timestamp):
        """Get firewall rules from a particular snapshot.

        Args:
            timestamp (int): The snapshot timestamp.

        Returns:
            list: FirewallRule

        Raises:
            MySQLError if a MySQL error occurs.
        """
        query = select_data.FIREWALL_RULES.format(timestamp)
        rows = self.execute_sql_with_fetch(
            resource.ResourceType.FIREWALL_RULE, query, ())
        return [self.map_row_to_object(firewall_rule.FirewallRule, row)
                for row in rows]
