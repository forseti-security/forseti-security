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

"""Explainer access_by_member tests"""

import pytest
import re
from endtoend_tests.helpers.forseti_cli import ForsetiCli


class TestExplainerAccessByMember:
    """Explainer access_by_member tests

    Run explain to verify access by member is working.
    """

    @pytest.mark.client
    @pytest.mark.e2e
    @pytest.mark.explainer
    def test_access_by_member(self, forseti_cli: ForsetiCli,
                              forseti_model_readonly,
                              forseti_server_service_account, organization_id,
                              project_id):
        """Explainer access_by_member tests

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
        result = forseti_cli.explainer_access_by_member(
            f'serviceaccount/{forseti_server_service_account}')

        # Assert Server SA has org browser role
        assert result.returncode == 0
        assert re.search(fr'"resources":[\s+]\[\\n'
                         fr'[\s+]*"organization\/{organization_id}"\\n'
                         fr'[\s+]*\],\\n'
                         fr'[\s+]*"role":[\s+]"roles\/browser"',
                         str(result.stdout))

        # Assert Server SA has org iam.securityReviewer role
        assert re.search(fr'"resources":[\s+]\[\\n'
                         fr'[\s+]*"organization\/{organization_id}"\\n'
                         fr'[\s+]*\],\\n'
                         fr'[\s+]*"role":[\s+]"roles\/iam.securityReviewer"',
                         str(result.stdout))

        # Assert Server SA has project cloudsql.client role
        assert re.search(fr'"resources":[\s+]\[\\n'
                         fr'[\s+]*"project\/{project_id}"\\n'
                         fr'[\s+]*\],\\n'
                         fr'[\s+]*"role":[\s+]"roles\/cloudsql.client"',
                         str(result.stdout))

    @pytest.mark.client
    @pytest.mark.e2e
    @pytest.mark.explainer
    def test_access_by_member_with_permission(self, forseti_cli: ForsetiCli,
                                              forseti_model_readonly,
                                              forseti_server_service_account,
                                              organization_id):
        """Explainer access_by_member with permission tests

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
        result = forseti_cli.explainer_access_by_member(
            f'serviceaccount/{forseti_server_service_account}',
            ['storage.buckets.list'])

        # Assert Server SA has org browser role
        assert re.search(fr'"resources":[\s+]\[\\n'
                         fr'[\s+]*"organization\/{organization_id}"\\n'
                         fr'[\s+]*\],\\n'
                         fr'[\s+]*"role":[\s+]"roles\/iam.securityReviewer"',
                         str(result.stdout))