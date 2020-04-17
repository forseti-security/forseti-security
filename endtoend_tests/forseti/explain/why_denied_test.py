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


class TestExplainerWhyDenied:
    """Explainer why_denied tests."""

    @pytest.mark.client
    @pytest.mark.e2e
    @pytest.mark.explainer
    def test_why_denied(self, forseti_cli: ForsetiCli, forseti_model_readonly,
                        forseti_server_service_account: str,
                        project_id: str):
        """Test why_denied for why the Forseti SA doesn't have the
        storage.buckets.delete permission.

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
        result = forseti_cli.explainer_why_denied(
            forseti_server_service_account, f'project/{project_id}',
            permissions=['storage.buckets.delete'])

        # Assert
        assert result.returncode == 0, f'Forseti stdout: {str(result.stdout)}'
        assert re.search(r'roles\/cloudmigration.inframanager', str(result.stdout))
        assert re.search(r'roles\/owner', str(result.stdout))
        assert re.search(r'roles\/storage.admin', str(result.stdout))
