# Copyright 2017 The Forseti Security Authors. All rights reserved.
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

"""KE Version Rule Scanner Tests."""

import unittest
import mock

from tests import unittest_utils
from google.cloud.security.common.gcp_type import (
    ke_cluster as ke_cluster_type)
from google.cloud.security.common.gcp_type import (
    organization as organization_type)
from google.cloud.security.common.gcp_type import project as project_type
from google.cloud.security.scanner.scanners import ke_version_scanner


# pylint: disable=bad-indentation
class FakeProjectDao(object):

    def get_project(self, project_id, snapshot_timestamp=0):
        return project_type.Project(project_id=project_id)


class FakeOrgDao(object):

    def find_ancestors(self, resource_id, snapshot_timestamp=0):
        return [organization_type.Organization(organization_id=123456)]


class KeVersionScannerTest(unittest_utils.ForsetiTestCase):

    def tearDown(self):
        self.org_patcher.stop()
        self.project_patcher.stop()

    def setUp(self):
        # patch the daos
        self.org_patcher = mock.patch(
            'google.cloud.security.common.data_access.'
            'org_resource_rel_dao.OrgResourceRelDao')
        self.mock_org_rel_dao = self.org_patcher.start()
        self.mock_org_rel_dao.return_value = FakeOrgDao()

        self.project_patcher = mock.patch(
            'google.cloud.security.common.data_access.'
            'project_dao.ProjectDao')
        self.mock_project_dao = self.project_patcher.start()
        self.mock_project_dao.return_value = FakeProjectDao()

        self.server_config = {
            'defaultClusterVersion': '1.7.11-gke.1',
            'validNodeVersions': [
                '1.8.6-gke.0',
                '1.7.11-gke.1',
                '1.7.10-gke.1',
                '1.6.13-gke.1',
            ],
            'defaultImageType': 'COS',
            'validImageTypes': [
                'UBUNTU',
                'COS'
            ],
            'validMasterVersions': [
                '1.8.6-gke.0',
                '1.7.11-gke.1'
            ]
        }

        self.ke_clusters = {
            # The main backend service.
            'master-version-invalid': ke_cluster_type.KeCluster.from_dict(
                'foo', self.server_config,
                {
                    'name': 'master-version-invalid',
                    'nodePools': [{
                        'name': 'default-pool',
                        'version': '1.6.13-gke.1'
                    }],
                    'initialClusterVersion': '1.6.13-gke.1',
                    'currentMasterVersion': '1.6.13-gke.1',
                    'currentNodeVersion': '1.6.13-gke.1'
                }),
            'node-version-invalid': ke_cluster_type.KeCluster.from_dict(
                'foo', self.server_config,
                {
                    'name': 'node-version-invalid',
                    'nodePools': [{
                        'name': 'default-pool',
                        'version': '1.8.4-gke.1'
                    }],
                    'initialClusterVersion': '1.8.4-gke.1',
                    'currentMasterVersion': '1.8.6-gke.0',
                    'currentNodeVersion': '1.8.4-gke.1'
                }),
            'node-version-not-allowed': ke_cluster_type.KeCluster.from_dict(
                'foo', self.server_config,
                {
                    'name': 'node-version-not-allowed',
                    'nodePools': [{
                        'name': 'default-pool',
                        'version': '1.7.10-gke.1'
                    }],
                    'initialClusterVersion': '1.7.10-gke.1',
                    'currentMasterVersion': '1.7.11-gke.1',
                    'currentNodeVersion': '1.7.10-gke.1'
                }),
            'multiple-node-pools': ke_cluster_type.KeCluster.from_dict(
                'foo', self.server_config,
                {
                    'name': 'multiple-node-pools',
                    'nodePools': [{
                        'name': 'default-pool',
                        'version': '1.7.11-gke.1'
                    }, {
                        'name': 'secondary-pool',
                        'version': '1.7.11-gke.1'
                    }],
                    'initialClusterVersion': '1.7.11-gke.1',
                    'currentMasterVersion': '1.7.11-gke.1',
                    'currentNodeVersion': '1.7.11-gke.1'
                })
        }
        self.scanner = ke_version_scanner.KeVersionScanner(
            {}, {}, '',
            unittest_utils.get_datafile_path(
                __file__, 'ke_version_scanner_test_data.yaml'))
        self.scanner._retrieve = mock.Mock(
            return_value=self.ke_clusters.values())

    @mock.patch.object(
        ke_version_scanner.KeVersionScanner,
        '_output_results_to_db', autospec=True)
    def test_run_scanner(self, mock_output_results):
        self.scanner.run()
        expected_violations = [
            {'resource_id': 'node-version-not-allowed',
             'resource_type': 'ke',
             'rule_index': 2,
             'rule_name': 'Disallowed node pool version',
             'violation_data': {'cluster_name': 'node-version-not-allowed',
                                'node_pool_name': 'default-pool',
                                'project_id': 'foo',
                                'violation_reason': (
                                    "Node pool version 1.7.10-gke.1 is not "
                                    "allowed (['>= 1.6.13-gke.1', "
                                    "'>= 1.7.11-gke.1', '>= 1.8.4-gke.1', "
                                    "'>= 1.9.*']).")},
             'violation_type': 'KE_VERSION_VIOLATION'},
            {'resource_id': 'master-version-invalid',
             'resource_type': 'ke',
             'rule_index': 1,
             'rule_name': 'Unsupported master version',
             'violation_data': {'cluster_name': 'master-version-invalid',
                                'node_pool_name': '',
                                'project_id': 'foo',
                                'violation_reason': (
                                    "Master version 1.6.13-gke.1 is not "
                                    "supported (['1.7.11-gke.1', "
                                    "'1.8.6-gke.0']).")},
             'violation_type': 'KE_VERSION_VIOLATION'},
            {'resource_id': 'node-version-invalid',
             'resource_type': 'ke',
             'rule_index': 0,
             'rule_name': 'Unsupported node pool version',
             'violation_data': {'cluster_name': 'node-version-invalid',
                                'node_pool_name': 'default-pool',
                                'project_id': 'foo',
                                'violation_reason': (
                                    "Node pool version 1.8.4-gke.1 is not "
                                    "supported (['1.6.13-gke.1', "
                                    "'1.7.10-gke.1', '1.7.11-gke.1', "
                                    "'1.8.6-gke.0']).")},
             'violation_type': 'KE_VERSION_VIOLATION'}]
        mock_output_results.assert_called_once_with(mock.ANY,
                                                    expected_violations)


if __name__ == '__main__':
    unittest.main()
