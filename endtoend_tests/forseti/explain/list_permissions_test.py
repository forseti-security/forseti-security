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


class TestExplainerListPermissions:
    """Explainer list_permissions tests."""

    @pytest.mark.client
    @pytest.mark.e2e
    @pytest.mark.explainer
    def test_list_permissions_for_iam(self, forseti_cli: ForsetiCli,
                                      forseti_model_readonly):
        """Test list_permissions for the iam.roleAdmin role includes the
        expected permissions.

        Args:
            forseti_cli (ForsetiCli): Instance of the forseti cli helper
            forseti_model_readonly (Tuple): Model name & process result
        """
        # Arrange
        model_name, _, _ = forseti_model_readonly
        forseti_cli.model_use(model_name=model_name)

        # Act
        result = forseti_cli.explainer_list_permissions(
            roles=['roles/iam.roleAdmin'])

        # Assert
        assert result.returncode == 0, f'Forseti stdout: {str(result.stdout)}'
        assert re.search(r'iam.roles.create', str(result.stdout))
        assert re.search(r'iam.roles.delete', str(result.stdout))
        assert re.search(r'iam.roles.get', str(result.stdout))
        assert re.search(r'iam.roles.list', str(result.stdout))
        assert re.search(r'iam.roles.undelete', str(result.stdout))
        assert re.search(r'iam.roles.update', str(result.stdout))
        assert re.search(r'resourcemanager.projects.get', str(result.stdout))
        assert re.search(r'resourcemanager.projects.getIamPolicy', str(result.stdout))

    @pytest.mark.client
    @pytest.mark.e2e
    @pytest.mark.explainer
    def test_list_permissions_for_storage(self, forseti_cli: ForsetiCli,
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
        result = forseti_cli.explainer_list_permissions(
            roles=['roles/storage.admin'])

        # Assert
        assert result.returncode == 0, f'Forseti stdout: {str(result.stdout)}'
        assert re.search(r'storage.buckets.create', str(result.stdout))
        assert re.search(r'storage.buckets.delete', str(result.stdout))
        assert re.search(r'storage.buckets.get', str(result.stdout))
        assert re.search(r'storage.buckets.getIamPolicy', str(result.stdout))
        assert re.search(r'storage.buckets.list', str(result.stdout))
        assert re.search(r'storage.buckets.setIamPolicy', str(result.stdout))
        assert re.search(r'storage.buckets.update', str(result.stdout))
        assert re.search(r'storage.objects.create', str(result.stdout))
        assert re.search(r'storage.objects.delete', str(result.stdout))
        assert re.search(r'storage.objects.get', str(result.stdout))
        assert re.search(r'storage.objects.getIamPolicy', str(result.stdout))
        assert re.search(r'storage.objects.list', str(result.stdout))
        assert re.search(r'storage.objects.setIamPolicy', str(result.stdout))
        assert re.search(r'storage.objects.update', str(result.stdout))

    @pytest.mark.client
    @pytest.mark.e2e
    @pytest.mark.explainer
    def test_list_permissions_with_role_prefix(self, forseti_cli: ForsetiCli,
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
        result = forseti_cli.explainer_list_permissions(
            role_prefixes=['roles/storage'])

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
