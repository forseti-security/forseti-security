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
from google.cloud.security.common.gcp_type import gce_network
from google.cloud.security.common.gcp_type import resource
from google.cloud.security.common.util import log_util
import json
import re

LOGGER = log_util.get_logger(__name__)


class NetworksDao(dao.Dao):
    """Instance DAO."""

    def get_networks(self, timestamp):
        """Get network info from a particular snapshot.

        Args:
            timestamp: The snapshot timestamp.

        Returns:
            A list of networks from a particular project

        Raises:
            MySQLError if a MySQL error occurs.
        """
        idao = instance_dao.InstanceDao()
        return list(set([self.parse_network_instance(instance) for instance in idao.get_instances(timestamp)]))

    # This is to parse the network info we have 
    def parse_network_instance(self, instance_object):
        network_dictionary = json.loads(instance_object.network_interfaces)
        if len(network_dictionary) > 1:
            LOGGER.error('Should only be one interface ties to an virtual instance.')
        
        network_url = network_dictionary[0]['network']
        network_and_project = re.search('compute\/v1\/projects\/([^\/]*).*networks\/([^\/]*)', network_url)
        project = network_and_project.group(1)
        network = network_and_project.group(2)
        is_external_network = "accessConfigs" in network_dictionary[0]
        return gce_network.GceNetwork(project, network, is_external_network)


def main():
    dn = NetworksDao()
    print(dn.get_networks('20170615T173104Z'))

if __name__ == '__main__':
    main()