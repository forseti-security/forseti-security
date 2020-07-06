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


class TestExplainerWhyGranted:
    """Explainer why_granted tests."""

    @pytest.mark.client
    @pytest.mark.e2e
    @pytest.mark.explainer
    def test_why_granted_permission_for_org(self, forseti_cli: ForsetiCli,
                                            forseti_model_readonly,
                                            forseti_server_service_account: str,
                                            organization_id: str):
        """Test why_granted for why the Forseti SA is granted permission for
        the org.

        Args:
            forseti_cli (ForsetiCli): Instance of the forseti cli helper
            forseti_model_readonly (Tuple): Model name & process result
            forseti_server_service_account (str): Server service account email
            organization_id (str): Org id being scanned
        """
        # Arrange
        model_name, _, _ = forseti_model_readonly
        forseti_cli.model_use(model_name=model_name)

        # Act
        result = forseti_cli.explainer_why_granted(
            f'serviceaccount/{forseti_server_service_account}',
            f'organization/{organization_id}',
            permission='iam.serviceAccounts.get')

        # Assert
        assert result.returncode == 0, f'Forseti stdout: {str(result.stdout)}'
        assert re.search(r'roles\/iam.securityReviewer', str(result.stdout))

    @pytest.mark.client
    @pytest.mark.e2e
    @pytest.mark.explainer
    def test_why_granted_permission_for_project(self, forseti_cli: ForsetiCli,
                                                forseti_model_readonly,
                                                forseti_server_service_account: str,
                                                project_id: str):
        """Test why_granted for why the Forseti SA is granted permission for
        the project.

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
        result = forseti_cli.explainer_why_granted(
            f'serviceaccount/{forseti_server_service_account}',
            f'project/{project_id}',
            permission='compute.instances.get')

        # Assert
        assert result.returncode == 0, f'Forseti stdout: {str(result.stdout)}'
        assert re.search(r'roles\/compute.networkViewer', str(result.stdout))

    @pytest.mark.client
    @pytest.mark.e2e
    @pytest.mark.explainer
    def test_why_granted_role_for_org(self, forseti_cli: ForsetiCli,
                                      forseti_model_readonly,
                                      forseti_server_service_account: str,
                                      organization_id: str):
        """Test why_granted for why the Forseti SA is granted role for
        the org.

        Args:
            forseti_cli (ForsetiCli): Instance of the forseti cli helper
            forseti_model_readonly (Tuple): Model name & process result
            forseti_server_service_account (str): Server service account email
            organization_id (str): Org id being scanned
        """
        # Arrange
        model_name, _, _ = forseti_model_readonly
        forseti_cli.model_use(model_name=model_name)

        # Act
        result = forseti_cli.explainer_why_granted(
            f'serviceaccount/{forseti_server_service_account}',
            f'organization/{organization_id}',
            role='roles/iam.securityReviewer')

        # Assert
        assert result.returncode == 0, f'Forseti stdout: {str(result.stdout)}'
        assert re.search(fr'organization\/{organization_id}', str(result.stdout))

    @pytest.mark.client
    @pytest.mark.e2e
    @pytest.mark.explainer
    def test_why_granted_role_for_project(self, forseti_cli: ForsetiCli,
                                          forseti_model_readonly,
                                          forseti_server_service_account: str,
                                          organization_id: str,
                                          project_id: str):
        """Test why_granted for why the Forseti SA is granted role for
        the project.

        Args:
            forseti_cli (ForsetiCli): Instance of the forseti cli helper
            forseti_model_readonly (Tuple): Model name & process result
            forseti_server_service_account (str): Server service account email
            organization_id (str): Org id being scanned
            project_id (str): Project id being scanned
        """
        # Arrange
        model_name, _, _ = forseti_model_readonly
        forseti_cli.model_use(model_name=model_name)

        # Act
        result = forseti_cli.explainer_why_granted(
            f'serviceaccount/{forseti_server_service_account}',
            f'project/{project_id}',
            role='roles/cloudsql.client')

        # Assert
        assert result.returncode == 0, f'Forseti stdout: {str(result.stdout)}'
        assert re.search(fr'organization\/{organization_id}', str(result.stdout))
