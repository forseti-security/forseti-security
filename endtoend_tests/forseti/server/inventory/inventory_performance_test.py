# Copyright 2020 The Forseti Security Authors. All rights reserved.
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

"""Inventory performance end-to-end test"""

import json
import pytest
import subprocess
from sqlalchemy.sql import text

EXPECTED_BIGQUERY_COUNT = 250000
EXPECTED_INVENTORY_STATUS = 'SUCCESS'
EXPECTED_INVENTORY_TIME = 15
EXPECTED_PROJECT_COUNT = 1000
EXPECTED_RESOURCE_COUNT = 296612


class TestInventoryPerformance:
    """Inventory Performance test

    Create an inventory and model using mocked CAI resources and assert
    the inventory is completed in 15 minutes or less, and that the mock
    resources are created in the inventory.
    """

    @pytest.mark.e2e
    @pytest.mark.inventory
    def test_inventory_performance(self,
                                   cai_dump_file_gcs_paths,
                                   cloudsql_connection,
                                   root_resource_id,
                                   server_config_helper,
                                   test_id):
        """Inventory performance test

        Args:
            cai_dump_file_gcs_paths (list): List of mock CAI dump files
            cloudsql_connection (object): SQLAlchemy engine connection for Forseti
            root_resource_id (str): Root resource id for inventory
            server_config_helper (object): ServerConfig helper class instance
            test_id (str): Random test id
        """
        # Arrange
        server_config = server_config_helper.read()

        # Set root resource id
        server_config['inventory']['root_resource_id'] = root_resource_id

        # Disable API polling
        for key in server_config['inventory']['api_quota']:
            server_config['inventory']['api_quota'][key]['disable_polling'] = True

        # Mock CAI export paths
        server_config['inventory']['cai']['cai_dump_file_gcs_paths'] = cai_dump_file_gcs_paths

        # Write and update config
        server_config_helper.write(server_config)

        # Act
        model_name = f'InvPerfTest{test_id}'
        cmd = ['forseti', 'inventory', 'create', '--import_as', model_name]
        subprocess.run(cmd,
                       stderr=subprocess.PIPE,
                       stdout=subprocess.PIPE)

        # Assert
        get_model_query = text('SELECT '
                               'M.description '
                               'FROM forseti_security.model M '
                               'WHERE M.name = :model_name;')
        model_description = (
            cloudsql_connection.execute(get_model_query, model_name=model_name)
            .fetchone())
        model_dict = json.loads(model_description[0])
        inventory_id = model_dict['source_info']['inventory_index_id']

        # Assert inventory status + time taken
        inventory_query = text('SELECT '
                               'I.inventory_status, '
                               'TIMESTAMPDIFF(MINUTE, I.created_at_datetime, '
                               'I.completed_at_datetime) AS InventoryLength '
                               'FROM forseti_security.inventory_index I '
                               'WHERE I.id = :inventory_id;')
        inventory = cloudsql_connection.execute(
            inventory_query, inventory_id=inventory_id).fetchone()
        assert EXPECTED_INVENTORY_STATUS == inventory[0]
        assert EXPECTED_INVENTORY_TIME >= inventory[1]

        # Assert resource count
        resource_count_query = text('SELECT '
                                    'COUNT(*) '
                                    'FROM forseti_security.gcp_inventory '
                                    'WHERE inventory_index_id = :inventory_id;')
        resource_count = cloudsql_connection.execute(
            resource_count_query, inventory_id=inventory_id).fetchone()
        assert EXPECTED_RESOURCE_COUNT == resource_count[0]

        # Assert Bigquery count
        bigquery_query = text('SELECT '
                              'COUNT(*) '
                              'FROM forseti_security.gcp_inventory '
                              'WHERE '
                              'inventory_index_id = :inventory_id '
                              'AND resource_type = \'bigquery_table\' '
                              'AND category = \'resource\';')
        bigquery_count = cloudsql_connection.execute(
            bigquery_query, inventory_id=inventory_id).fetchone()
        assert EXPECTED_BIGQUERY_COUNT == bigquery_count[0]

        # Assert Project count
        project_query = text('SELECT '
                             'COUNT(*) '
                             'FROM forseti_security.gcp_inventory '
                             'WHERE '
                             'inventory_index_id = :inventory_id '
                             'AND resource_type = \'project\';')
        project_count = cloudsql_connection.execute(
            project_query, inventory_id=inventory_id).fetchone()
        assert EXPECTED_PROJECT_COUNT == project_count[0]
