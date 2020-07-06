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


class TestExplainerGetPolicy:
    """Explainer get_policy tests."""

    @pytest.mark.client
    @pytest.mark.e2e
    @pytest.mark.explainer
    def test_get_policy(self, forseti_cli: ForsetiCli, forseti_model_readonly,
                        forseti_server_service_account, project_id):
        """Test get_policy with Forseti SA includes storage.objects.get
        permission on Forseti project.

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
        result = forseti_cli.explainer_check_policy(
            f'project/{project_id}', 'storage.objects.get',
            f'serviceAccount/{forseti_server_service_account}')

        # Assert
        assert result.returncode == 0, f'Forseti stdout: {str(result.stdout)}'
        assert re.search(fr'"result":[\s+]true', str(result.stdout))
