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

"""Inventory tests"""

import pytest
import re
import subprocess
from endtoend_tests.helpers.forseti_cli import ForsetiCli
from sqlalchemy.sql import text


class TestInventory:
    """Inventory tests

    Execute the basic inventory functionality such as: create, get, delete, etc.
    """

    @pytest.mark.e2e
    @pytest.mark.inventory
    @pytest.mark.server
    def test_inventory_cai_gcs_export(self, forseti_inventory_readonly,
                                      forseti_server_bucket_name,
                                      organization_id):
        # Arrange
        inventory_id, _ = forseti_inventory_readonly
        expected_path = f'gs://{forseti_server_bucket_name}/organizations-{organization_id}-resource-{inventory_id}.dump'

        # Act
        cmd = ['sudo', 'gsutil', 'ls', expected_path]
        result = subprocess.run(cmd, stderr=subprocess.PIPE,
                                stdout=subprocess.PIPE)

        # Assert
        assert result.returncode == 0

    @pytest.mark.e2e
    @pytest.mark.inventory
    @pytest.mark.server
    def test_inventory_create(self, cloudsql_connection,
                              forseti_inventory_readonly):
        # Arrange/act
        inventory_id, result = forseti_inventory_readonly

        # Assert status code
        assert result.returncode == 0

        # Assert inventory status is PARTIAL_SUCCESS
        # TODO: Make inventory SUCCESS by adding G Suite integration
        query = text('SELECT '
                     'inventory_status '
                     'FROM forseti_security.inventory_index '
                     'WHERE '
                     f"id = '{inventory_id}'")
        inventory_status = cloudsql_connection.execute(query).fetchone()
        assert inventory_status
        assert inventory_status == 'SUCCESS'

        # Assert inventory counts
        query = text('SELECT '
                     'COUNT(*) '
                     'FROM forseti_security.gcp_inventory '
                     'WHERE '
                     f"inventory_index_id = '{inventory_id}'")
        inventory_counts = cloudsql_connection.execute(query).fetchone()
        assert inventory_counts
        assert inventory_counts[0] > 0

        # Assert inventory lifecycle state
        # describe command("mysql -u #{db_user_name} -p#{db_password} --host 127.0.0.1 --database forseti_security --execute \"SELECT count(DISTINCT resource_data->>'$.lifecycleState') FROM gcp_inventory WHERE category = 'resource' and resource_type = 'project' and resource_data->>'$.lifecycleState' = 'ACTIVE';\"") do
        query = text('SELECT '
                     "COUNT(DISTINCT resource_data->>'$.lifecycleState') "
                     'FROM forseti_security.gcp_inventory '
                     'WHERE '
                     "category = 'resource' "
                     "AND resource_type = 'project' "
                     "AND resource_data->>'$.lifecycleState' = 'ACTIVE'")
        inventory_lifecycle_state = cloudsql_connection.execute(query).fetchone()
        assert inventory_lifecycle_state
        assert inventory_lifecycle_state[0] == 1

    @pytest.mark.e2e
    @pytest.mark.inventory
    @pytest.mark.server
    def test_inventory_delete(self, forseti_cli: ForsetiCli):
        # Arrange
        inventory_id, result = forseti_cli.inventory_create()

        # Assert inventory exists

        # Act
        forseti_cli.inventory_delete(inventory_id)

        # Assert
        assert result.returncode == 0
        assert re.search(inventory_id, str(result.stdout))

    @pytest.mark.e2e
    @pytest.mark.inventory
    @pytest.mark.server
    def test_inventory_get(self, forseti_cli: ForsetiCli,
                           forseti_inventory_readonly):
        # Arrange
        inventory_id, _ = forseti_inventory_readonly

        # Act
        result = forseti_cli.inventory_get(inventory_id)

        # Assert
        assert result.returncode == 0
        assert re.search(inventory_id, str(result.stdout))

    @pytest.mark.e2e
    @pytest.mark.inventory
    @pytest.mark.server
    def test_inventory_list(self, forseti_cli: ForsetiCli,
                           forseti_inventory_readonly):
        # Arrange
        inventory_id, _ = forseti_inventory_readonly

        # Act
        result = forseti_cli.inventory_list()

        # Assert
        assert result.returncode == 0
        assert re.search(inventory_id, str(result.stdout))
