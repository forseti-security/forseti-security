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
from tests.services.util.db import create_test_engine
from google.cloud.forseti.common.gcp_type import resource as resource_mod
from google.cloud.forseti.scanner.scanners import ke_version_scanner
from google.cloud.forseti.services.dao import ModelManager
from google.cloud.forseti.services.inventory.base.resources import size_t_hash

SERVER_CONFIG = """
{
  "defaultClusterVersion": "1.7.11-gke.1",
  "validNodeVersions": [
      "1.8.6-gke.0",
      "1.7.11-gke.1",
      "1.7.10-gke.1",
      "1.6.13-gke.1"
  ],
  "defaultImageType": "COS",
  "validImageTypes": [
      "UBUNTU",
      "COS"
  ],
  "validMasterVersions": [
      "1.8.6-gke.0",
      "1.7.11-gke.1"
  ]
}
"""

MASTER_VERSION_INVALID = """
{
    "name": "master-version-invalid",
    "nodePools": [{
        "name": "default-pool",
        "version": "1.6.13-gke.1"
    }],
    "initialClusterVersion": "1.6.13-gke.1",
    "currentMasterVersion": "1.6.13-gke.1",
    "currentNodeVersion": "1.6.13-gke.1",
    "selfLink": "master-version-invalid.com"
}
"""

NODE_VERSION_INVALID = """
{
    "name": "node-version-invalid",
    "nodePools": [{
        "name": "default-pool",
        "version": "1.8.4-gke.1"
    }],
    "initialClusterVersion": "1.8.4-gke.1",
    "currentMasterVersion": "1.8.6-gke.0",
    "currentNodeVersion": "1.8.4-gke.1",
    "selfLink": "node-version-invalid.com"
}
"""

NODE_VERSION_NOT_ALLOWED = """
{
    "name": "node-version-not-allowed",
    "nodePools": [{
        "name": "default-pool",
        "version": "1.7.10-gke.1"
    }],
    "initialClusterVersion": "1.7.10-gke.1",
    "currentMasterVersion": "1.7.11-gke.1",
    "currentNodeVersion": "1.7.10-gke.1",
    "selfLink": "node-version-not-allowed.com"
}
"""

MULTIPLE_NODE_POOLS = """
{
    "name": "multiple-node-pools",
    "nodePools": [{
        "name": "default-pool",
        "version": "1.7.11-gke.1"
    }, {
        "name": "secondary-pool",
        "version": "1.7.11-gke.1"
    }],
    "initialClusterVersion": "1.7.11-gke.1",
    "currentMasterVersion": "1.7.11-gke.1",
    "currentNodeVersion": "1.7.11-gke.1",
    "selfLink": "multiple-node-pools.com"
}
"""

MASTER_VERSION_INVALID_ID = size_t_hash('master-version-invalid.com')
NODE_VERSION_INVALID_ID = size_t_hash('node-version-invalid.com')
NODE_VERSION_NOT_ALLOWED_ID = size_t_hash('node-version-not-allowed.com')
MULTIPLE_NODE_POOLS_ID = size_t_hash('multiple-node-pools.com')

FAKE_CLUSTERS = {
    MASTER_VERSION_INVALID_ID: MASTER_VERSION_INVALID,
    NODE_VERSION_INVALID_ID: NODE_VERSION_INVALID,
    NODE_VERSION_NOT_ALLOWED_ID: NODE_VERSION_NOT_ALLOWED,
    MULTIPLE_NODE_POOLS_ID: MULTIPLE_NODE_POOLS,
}


class FakeServiceConfig(object):

    def __init__(self):
        engine = create_test_engine()
        self.model_manager = ModelManager(engine)


# pylint: disable=bad-indentation
class KeVersionScannerTest(unittest_utils.ForsetiTestCase):

    @classmethod
    def setUpClass(cls):
        cls.service_config = FakeServiceConfig()
        cls.model_name = cls.service_config.model_manager.create(
            name='iap-scanner-test')

        scoped_session, data_access = (
            cls.service_config.model_manager.get(cls.model_name))

        # Add organization and project to model.
        with scoped_session as session:
            organization = data_access.add_resource_by_name(
                session, 'organization/12345', '', True)
            project = data_access.add_resource(session, 'project/foo',
                                               organization)
            for name, data in FAKE_CLUSTERS.items():
                ke_cluster = data_access.add_resource(
                    session, 'kubernetes_cluster/%s' % name,
                    project)
                ke_cluster.data = data
                sc = data_access.add_resource(
                    session, 'kubernetes_service_config/%s' % name,
                    ke_cluster)
                sc.data = SERVER_CONFIG

            session.commit()

    def setUp(self):

        self.scanner = ke_version_scanner.KeVersionScanner(
            {}, {}, self.service_config, self.model_name,
            '', unittest_utils.get_datafile_path(
                __file__, 'ke_version_scanner_test_data.yaml'))

    @mock.patch.object(
        ke_version_scanner.KeVersionScanner,
        '_output_results_to_db', autospec=True)
    def test_run_scanner(self, mock_output_results):
        self.scanner.run()
        expected_violations = [
            {'resource_id': NODE_VERSION_NOT_ALLOWED_ID,
             'resource_name': u'node-version-not-allowed',
             'rule_name': 'Disallowed node pool version',
             'resource_data': '{"currentMasterVersion": "1.7.11-gke.1", "currentNodeVersion": "1.7.10-gke.1", "initialClusterVersion": "1.7.10-gke.1", "name": "node-version-not-allowed", "nodePools": [{"name": "default-pool", "version": "1.7.10-gke.1"}], "selfLink": "node-version-not-allowed.com"}',
             'full_name': u'organization/12345/project/foo/kubernetes_cluster/{}/'.format(NODE_VERSION_NOT_ALLOWED_ID),
             'rule_index': 2,
             'violation_data': {
                 'violation_reason': (
                     u"Node pool version 1.7.10-gke.1 is not allowed (['>= "
                     "1.6.13-gke.1', '>= 1.7.11-gke.1', '>= 1.8.4-gke.1', "
                     "'>= 1.9.*'])."),
                 'cluster_name': u'node-version-not-allowed',
                 'project_id': u'foo',
                 'full_name': u'organization/12345/project/foo/kubernetes_cluster/{}/'.format(NODE_VERSION_NOT_ALLOWED_ID),
                 'node_pool_name': u'default-pool'},
             'violation_type': 'KE_VERSION_VIOLATION',
             'resource_type': resource_mod.ResourceType.KE_CLUSTER},
            {'resource_id': MASTER_VERSION_INVALID_ID,
             'resource_name': u'master-version-invalid',
             'rule_name': 'Unsupported master version',
             'resource_data': '{"currentMasterVersion": "1.6.13-gke.1", "currentNodeVersion": "1.6.13-gke.1", "initialClusterVersion": "1.6.13-gke.1", "name": "master-version-invalid", "nodePools": [{"name": "default-pool", "version": "1.6.13-gke.1"}], "selfLink": "master-version-invalid.com"}',
             'full_name': u'organization/12345/project/foo/kubernetes_cluster/{}/'.format(MASTER_VERSION_INVALID_ID),
             'rule_index': 1,
             'violation_data': {
                 'violation_reason': (
                     u"Master version 1.6.13-gke.1 is not supported "
                     "([u'1.7.11-gke.1', u'1.8.6-gke.0'])."),
                 'cluster_name': u'master-version-invalid',
                 'project_id': u'foo',
                 'full_name': u'organization/12345/project/foo/kubernetes_cluster/{}/'.format(MASTER_VERSION_INVALID_ID),
                 'node_pool_name': ''},
             'violation_type': 'KE_VERSION_VIOLATION',
             'resource_type': resource_mod.ResourceType.KE_CLUSTER},
            {'resource_id': NODE_VERSION_INVALID_ID,
             'resource_name': u'node-version-invalid',
             'rule_name': 'Unsupported node pool version',
             'resource_data': '{"currentMasterVersion": "1.8.6-gke.0", "currentNodeVersion": "1.8.4-gke.1", "initialClusterVersion": "1.8.4-gke.1", "name": "node-version-invalid", "nodePools": [{"name": "default-pool", "version": "1.8.4-gke.1"}], "selfLink": "node-version-invalid.com"}',
             'full_name': u'organization/12345/project/foo/kubernetes_cluster/{}/'.format(NODE_VERSION_INVALID_ID),
             'rule_index': 0,
             'violation_data': {
                 'violation_reason': (
                     u"Node pool version 1.8.4-gke.1 is not supported "
                     "([u'1.6.13-gke.1', u'1.7.10-gke.1', u'1.7.11-gke.1', "
                     "u'1.8.6-gke.0'])."),
                 'cluster_name': u'node-version-invalid',
                 'project_id': u'foo',
                 'full_name': u'organization/12345/project/foo/kubernetes_cluster/{}/'.format(NODE_VERSION_INVALID_ID),
                 'node_pool_name': u'default-pool'},
             'violation_type': 'KE_VERSION_VIOLATION',
             'resource_type': resource_mod.ResourceType.KE_CLUSTER}]

        # Get the violations from the first call to the mock object.
        # call objects in Mock.mock_calls, are three-tuples of
        # (name, positional args, keyword args).
        results = mock_output_results.mock_calls[0][1][1]
        # Order of results is undefined, so sort before comparing
        self.assertEqual(
            sorted(expected_violations, key=lambda k: k['rule_index']),
            sorted(results, key=lambda k: k['rule_index']))


if __name__ == '__main__':
    unittest.main()
