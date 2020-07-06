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


class TestExplainerListRoles:
    """Explainer list_roles tests."""

    @pytest.mark.client
    @pytest.mark.e2e
    @pytest.mark.explainer
    def test_list_roles(self, forseti_cli: ForsetiCli, forseti_model_readonly):
        """Test list_roles includes the expected roles.

        Args:
            forseti_cli (ForsetiCli): Instance of the forseti cli helper
            forseti_model_readonly (Tuple): Model name & process result
        """
        # Arrange
        model_name, _, _ = forseti_model_readonly
        forseti_cli.model_use(model_name=model_name)

        # Act
        result = forseti_cli.explainer_list_roles()

        # Assert
        assert result.returncode == 0, f'Forseti stdout: {str(result.stdout)}'
        assert re.search(r'roles\/cloudtrace.user', str(result.stdout))
        assert re.search(r'roles\/compute.admin', str(result.stdout))
        assert re.search(r'roles\/storage.objectAdmin', str(result.stdout))
        assert re.search(r'roles\/stackdriver.accounts.viewer', str(result.stdout))
        assert re.search(r'roles\/serviceusage.serviceUsageViewer', str(result.stdout))
        assert re.search(r'roles\/servicemanagement.quotaAdmin', str(result.stdout))
        assert re.search(r'roles\/securitycenter.sourcesEditor', str(result.stdout))
        assert re.search(r'roles\/securitycenter.findingsStateSetter', str(result.stdout))
        assert re.search(r'roles\/securitycenter.findingsEditor', str(result.stdout))
        assert re.search(r'roles\/pubsub.editor', str(result.stdout))
        assert re.search(r'roles\/monitoring.viewer', str(result.stdout))
        assert re.search(r'roles\/container.clusterViewer', str(result.stdout))
        assert re.search(r'roles\/dataflow.worker', str(result.stdout))
        assert re.search(r'roles\/datastore.viewer', str(result.stdout))

    @pytest.mark.client
    @pytest.mark.e2e
    @pytest.mark.explainer
    def test_list_roles_with_iam_prefix(self, forseti_cli: ForsetiCli,
                                        forseti_model_readonly):
        """Test list_permissions for the storage.admin role includes the
        expected permissions.

        Args:
            forseti_cli (ForsetiCli): Instance of the forseti cli helper
            forseti_model_readonly (Tuple): Model name & process result
        """
        # Arrange
        model_name, _, _ = forseti_model_readonly
        forseti_cli.model_use(model_name=model_name)

        # Act
        result = forseti_cli.explainer_list_roles('roles/iam')

        # Assert
        assert result.returncode == 0, f'Forseti stdout: {str(result.stdout)}'
        assert re.search(r'roles\/iam.organizationRoleAdmin', str(result.stdout))
        assert re.search(r'roles\/iam.organizationRoleViewer', str(result.stdout))
        assert re.search(r'roles\/iam.roleAdmin', str(result.stdout))
        assert re.search(r'roles\/iam.roleViewer', str(result.stdout))
        assert re.search(r'roles\/iam.securityAdmin', str(result.stdout))
        assert re.search(r'roles\/iam.securityReviewer', str(result.stdout))
        assert re.search(r'roles\/iam.serviceAccountAdmin', str(result.stdout))
        assert re.search(r'roles\/iam.serviceAccountCreator', str(result.stdout))
        assert re.search(r'roles\/iam.serviceAccountDeleter', str(result.stdout))
        assert re.search(r'roles\/iam.serviceAccountKeyAdmin', str(result.stdout))
        assert re.search(r'roles\/iam.serviceAccountTokenCreator', str(result.stdout))
        assert re.search(r'roles\/iam.serviceAccountUser', str(result.stdout))
        assert re.search(r'roles\/iam.workloadIdentityUser', str(result.stdout))

    @pytest.mark.client
    @pytest.mark.e2e
    @pytest.mark.explainer
    def test_list_roles_with_storage_prefix(self, forseti_cli: ForsetiCli,
                                            forseti_model_readonly):
        """Test list_permissions with storage role prefix includes the
        expected roles.

        Args:
            forseti_cli (ForsetiCli): Instance of the forseti cli helper
            forseti_model_readonly (Tuple): Model name & process result
        """
        # Arrange
        model_name, _, _ = forseti_model_readonly
        forseti_cli.model_use(model_name=model_name)

        # Act
        result = forseti_cli.explainer_list_roles('roles/storage')

        # Assert
        assert result.returncode == 0, f'Forseti stdout: {str(result.stdout)}'
        assert re.search(r'roles\/storage.admin', str(result.stdout))
        assert re.search(r'roles\/storage.hmacKeyAdmin', str(result.stdout))
        assert re.search(r'roles\/storage.legacyBucketOwner', str(result.stdout))
        assert re.search(r'roles\/storage.legacyBucketReader', str(result.stdout))
        assert re.search(r'roles\/storage.legacyBucketWriter', str(result.stdout))
        assert re.search(r'roles\/storage.legacyObjectOwner', str(result.stdout))
        assert re.search(r'roles\/storage.legacyObjectReader', str(result.stdout))
        assert re.search(r'roles\/storage.objectAdmin', str(result.stdout))
        assert re.search(r'roles\/storage.objectCreator', str(result.stdout))
        assert re.search(r'roles\/storage.objectViewer', str(result.stdout))
        assert re.search(r'roles\/storagetransfer.admin', str(result.stdout))
        assert re.search(r'roles\/storagetransfer.user', str(result.stdout))
        assert re.search(r'roles\/storagetransfer.viewer', str(result.stdout))
