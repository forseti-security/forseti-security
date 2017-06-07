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

"""Data access object for networks instance."""
from google.cloud.security.common.data_access import dao
from google.cloud.security.common.data_access import instance_dao
from google.cloud.security.common.data_access.sql_queries import select_data
from google.cloud.security.common.gcp_type import instance
from google.cloud.security.common.gcp_type import resource
from google.cloud.security.common.util import log_util
import re
LOGGER = log_util.get_logger(__name__)


class NetworksDao(dao.Dao):
    """Instance DAO."""

    def get_network(self, timestamp):
        """Get network info from a particular snapshot.

        Args:
            timestamp: The snapshot timestamp.

        Returns:
            A list of networks from a particular project

        Raises:
            MySQLError if a MySQL error occurs.
        """
        idao = instance_dao.InstanceDao()
        network_project_names = set([self.parse_network_name(instance) for instance in idao.get_instances(timestamp)])
        return [network_and_project.split(",") for network_and_project in network_project_names]

    # This is to parse the network info we have 
    def parse_network_name(self, instance_object):
        #make this grab stuff from the 'network' work in url instead of first url
        network_url = re.findall('http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', instance_object.network_interfaces)[0]
        project = network_url.partition('projects/')[-1].partition('/')[0]
        network = network_url.partition('networks/')[-1]
        return ','.join([project, network])