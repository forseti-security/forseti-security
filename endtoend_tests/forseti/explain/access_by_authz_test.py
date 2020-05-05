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


class TestExplainerAccessByAuthz:
    """Explainer access_by_authz tests."""

    @pytest.mark.client
    @pytest.mark.e2e
    @pytest.mark.explainer
    def test_access_by_authz_with_permission(self, forseti_cli: ForsetiCli,
                                             forseti_model_readonly,
                                             project_id):
        """Test access_by_authz with permission includes Forseti project id.

        Args:
            forseti_cli (ForsetiCli): Instance of the forseti cli helper
            forseti_model_readonly (Tuple): Model name & process result
            project_id (str): Project id being scanned
        """
        # Arrange
        model_name, _, _ = forseti_model_readonly
        forseti_cli.model_use(model_name=model_name)

        # Act
        result = forseti_cli.explainer_access_by_authz(
            permission='iam.serviceAccounts.get')

        # Assert
        assert result.returncode == 0, f'Forseti stdout: {str(result.stdout)}'
        assert re.search(fr'"resource":[\s+]"project\/{project_id}"',
                         str(result.stdout))
        assert re.search(fr'"role":[\s+]"roles\/editor"', str(result.stdout))

    @pytest.mark.client
    @pytest.mark.e2e
    @pytest.mark.explainer
    def test_access_by_authz_with_role(self, forseti_cli: ForsetiCli,
                                       forseti_model_readonly,
                                       forseti_server_service_account,
                                       project_id):
        """Test access_by_authz with role includes Forseti project id.

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
        result = forseti_cli.explainer_access_by_authz(
            role='roles/storage.objectCreator')

        # Assert
        assert result.returncode == 0, f'Forseti stdout: {str(result.stdout)}'
        assert re.search(fr'{project_id}', str(result.stdout))
        assert re.search(fr'serviceaccount\/{forseti_server_service_account}',
                         str(result.stdout))
