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

"""Model tests"""

import pytest
import re
from endtoend_tests.helpers.forseti_cli import ForsetiCli
from sqlalchemy.sql import text


class TestModel:
    """Model tests

    Execute the basic model functionality such as: create, get, use, etc.
    """

    @pytest.mark.e2e
    @pytest.mark.model
    @pytest.mark.server
    def test_model_create(self, cloudsql_connection, forseti_cli: ForsetiCli,
                          forseti_model_readonly):
        # Arrange
        model_name, handle, _ = forseti_model_readonly

        # Act
        result = forseti_cli.model_get(model_name)

        # Assert
        assert handle
        assert re.search(fr'{handle}', str(result.stdout))

        # Assert model in database
        query = text('SELECT '
                     'state '
                     'FROM forseti_security.model '
                     'WHERE '
                     f"name = '{model_name}'")
        model = cloudsql_connection.execute(query).fetchone()
        assert model
        assert model[0] == 'PARTIAL_SUCCESS'

    @pytest.mark.e2e
    @pytest.mark.model
    @pytest.mark.server
    def test_model_delete(self, cloudsql_connection, forseti_cli: ForsetiCli,
                          forseti_inventory_readonly, test_id: str):
        # Arrange
        inventory_id, _ = forseti_inventory_readonly
        model_name = f'TMD{test_id}'
        _, _ = forseti_cli.model_create(inventory_id, model_name)

        # Assert model was created
        query = text('SELECT '
                     'COUNT(*) '
                     'FROM forseti_security.model '
                     'WHERE '
                     f"name = '{model_name}'")
        model_created = cloudsql_connection.execute(query).fetchone()
        assert model_created
        assert model_created[0] == 1

        # Act
        result = forseti_cli.model_delete(model_name)

        # Assert
        assert re.search(r'SUCCESS', str(result.stdout))

        # Assert model deleted from  database
        query = text('SELECT '
                     'COUNT(*) '
                     'FROM forseti_security.model '
                     'WHERE '
                     f"name = '{model_name}'")
        model_deleted = cloudsql_connection.execute(query).fetchone()
        assert model_deleted
        assert model_deleted[0] == 0

    @pytest.mark.client
    @pytest.mark.e2e
    @pytest.mark.model
    def test_model_get(self, forseti_cli: ForsetiCli, forseti_model_readonly):
        # Arrange
        model_name, handle, _ = forseti_model_readonly

        # Act
        result = forseti_cli.model_get(model_name)

        # Assert
        assert handle
        assert re.search(fr'{handle}', str(result.stdout))

    @pytest.mark.client
    @pytest.mark.e2e
    @pytest.mark.model
    def test_model_list(self, forseti_cli: ForsetiCli, forseti_model_readonly):
        # Arrange
        model_name, handle, _ = forseti_model_readonly

        # Act
        result = forseti_cli.model_get(model_name)

        # Assert
        assert handle
        assert re.search(fr'{handle}', str(result.stdout))

    @pytest.mark.e2e
    @pytest.mark.model
    @pytest.mark.server
    def test_model_roles(self, cloudsql_connection, forseti_model_readonly):
        # Arrange/Act
        model_name, handle, _ = forseti_model_readonly

        # Assert
        table_name = f'forseti_security.{handle}_roles'
        query = text('SELECT '
                     'COUNT(*) '
                     f'FROM {table_name}')
        model_roles = (cloudsql_connection.execute(query).fetchone())
        assert model_roles
        assert model_roles[0] > 0


    @pytest.mark.client
    @pytest.mark.e2e
    @pytest.mark.model
    def test_model_use(self, forseti_cli: ForsetiCli, forseti_model_readonly):
        # Arrange
        model_name, handle, _ = forseti_model_readonly

        # Act
        forseti_cli.model_use(model_name)
        result = forseti_cli.config_show()

        # Assert
        assert handle
        assert re.search(fr'{handle}', str(result.stdout))
