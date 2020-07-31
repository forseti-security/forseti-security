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

import pytest
import re
from endtoend_tests.helpers.forseti_cli import ForsetiCli

# These values are the number of roles assigned to the Forseti server SA.
# They will need to be updated as the roles change.
EXPECTED_COUNT_FOR_ORG = 11
EXPECTED_COUNT_FOR_PROJECT = 18


class TestExplainerAccessByResource:
    """Explainer access_by_resource tests.

    TODO: Tests take a long time for explain commands, use different resources?
    """

    @pytest.mark.client
    @pytest.mark.e2e
    @pytest.mark.explainer
    def test_access_by_resource_for_organization(self, forseti_cli: ForsetiCli,
                                                 forseti_model_readonly,
                                                 forseti_server_service_account,
                                                 organization_id):
        """Test access_by_resource for organization includes Forseti SA.

        Args:
            forseti_cli (ForsetiCli): Instance of the forseti cli helper
            forseti_model_readonly (Tuple): Model name & process result
            forseti_server_service_account (str): Server service account email
            organization_id (str): Organization id being scanned
        """
        # Arrange
        model_name, _, _ = forseti_model_readonly
        forseti_cli.model_use(model_name=model_name)

        # Act
        result = forseti_cli.explainer_access_by_resource(
            f'organization/{organization_id}')

        # Assert
        assert result.returncode == 0, f'Forseti stdout: {str(result.stdout)}'
        assert EXPECTED_COUNT_FOR_ORG == len(re.findall(forseti_server_service_account, str(result.stdout)))

    @pytest.mark.client
    @pytest.mark.e2e
    @pytest.mark.explainer
    def test_access_by_resource_for_project(self, forseti_cli: ForsetiCli,
                                            forseti_model_readonly,
                                            forseti_server_service_account,
                                            project_id):
        """Test access_by_resource for project includes Forseti SA.

        Args:
            forseti_cli (ForsetiCli): Instance of the forseti cli helper
            forseti_model_readonly (Tuple): Model name & process result
            forseti_server_service_account (str): Server service account email
            project_id (str): Project id being scanned
        """
        # Arrange
        model_name, _, _ = forseti_model_readonly
        forseti_cli.model_use(model_name=model_name)

        # Act
        result = forseti_cli.explainer_access_by_resource(
            f'project/{project_id}')

        # Assert
        assert result.returncode == 0, f'Forseti stdout: {str(result.stdout)}'
        assert EXPECTED_COUNT_FOR_PROJECT == len(re.findall(forseti_server_service_account, str(result.stdout)))
