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

"""KE Rule Scanner Tests."""

from builtins import object
import unittest
import mock

from tests import unittest_utils
from tests.services.util.db import create_test_engine
from google.cloud.forseti.scanner.scanners import ke_scanner
from google.cloud.forseti.services.dao import ModelManager
from google.cloud.forseti.services.inventory.base.resources import size_t_hash

SERVER_CONFIG = '''
{
}
'''

FAKE_CLUSTER = '''
{
    "name": "fake-cluster",
    "nodePools": [
        {
            "name": "default-pool",
            "version": "1.7.11-gke.1",
            "config": {
                "imageType": "COS"
            }
        },
        {
            "name": "secondary-pool",
            "version": "1.7.11-gke.1",
            "config": {
                "imageType": "COS"
            }
        }
    ],
    "addonsConfig": {
        "httpLoadBalancing": {},
        "kubernetesDashboard": {
            "disabled": true
        },
        "istioConfig": {
            "auth": "AUTH_MUTUAL_TLS"
        }
    },
    "selfLink": "fake-cluster.com"
}
'''

FAKE_CLUSTER_ID = size_t_hash('fake-cluster.com')

NO_NODE_POOLS = '''
{
    "name": "fake-cluster-no-node-pools",
    "addonsConfig": {
        "httpLoadBalancing": {},
        "kubernetesDashboard": {
            "disabled": true
        },
        "istioConfig": {
            "auth": "AUTH_MUTUAL_TLS"
        }
    },
    "selfLink": "fake-cluster-no-node-pools.com"
}
'''

NO_NODE_POOLS_ID = size_t_hash('fake-cluster-no-node-pools.com')

FAKE_CLUSTERS = {
    FAKE_CLUSTER_ID: FAKE_CLUSTER,
    NO_NODE_POOLS_ID: NO_NODE_POOLS,
}


class FakeServiceConfig(object):

    def __init__(self):
        engine = create_test_engine()
        self.model_manager = ModelManager(engine)


class KeScannerTest(unittest_utils.ForsetiTestCase):

    @classmethod
    def setUpClass(cls):
        cls.service_config = FakeServiceConfig()
        cls.model_name = cls.service_config.model_manager.create(
            name='ke-scanner-test')

        scoped_session, data_access = (
            cls.service_config.model_manager.get(cls.model_name))

        # Add organization and project to model.
        with scoped_session as session:
            organization = data_access.add_resource_by_name(
                session, 'organization/12345', '', True)
            project = data_access.add_resource(session, 'project/fake-project',
                                               organization)

            for cluster_id, cluster in list(FAKE_CLUSTERS.items()):
                ke_cluster = data_access.add_resource(
                    session,
                    'kubernetes_cluster/{}'.format(cluster_id),
                    project,
                )

                ke_cluster.data = cluster

                sc = data_access.add_resource(
                    session,
                    'kubernetes_service_config/{}'.format(cluster_id),
                    ke_cluster,
                )
                sc.data = SERVER_CONFIG

            session.commit()

    def setUp(self):

        self.scanner = ke_scanner.KeScanner(
            {}, {}, self.service_config, self.model_name,
            '', unittest_utils.get_datafile_path(
                __file__, 'ke_scanner_test_data.yaml'))

    @mock.patch(
        'google.cloud.forseti.scanner.audit.ke_rules_engine.LOGGER',
        autospsec=True,
    )
    @mock.patch.object(
        ke_scanner.KeScanner,
        '_output_results_to_db', autospec=True)
    def test_run_scanner(self, mock_output_results, mock_logger):
        self.scanner.run()
        expected_violations = [
            {'rule_name': 'explicit whitelist, pass',
             'resource_name': 'fake-cluster-no-node-pools',
             'resource_data': '{"addonsConfig": {"httpLoadBalancing": {}, "istioConfig": {"auth": "AUTH_MUTUAL_TLS"}, "kubernetesDashboard": {"disabled": true}}, "name": "fake-cluster-no-node-pools", "selfLink": "fake-cluster-no-node-pools.com"}',
             'full_name': 'organization/12345/project/fake-project/kubernetes_cluster/{}/'.format(NO_NODE_POOLS_ID),
             'resource_id': NO_NODE_POOLS_ID,
             'rule_index': 0,
             'violation_type': 'KE_VIOLATION',
             'violation_data': {'violation_reason': "name has value fake-cluster-no-node-pools, which is not in the whitelist (['fake-cluster'])", 'cluster_name': 'fake-cluster-no-node-pools', 'project_id': 'fake-project', 'full_name': 'organization/12345/project/fake-project/kubernetes_cluster/{}/'.format(NO_NODE_POOLS_ID)},
             'resource_type': 'kubernetes_cluster'},

            {'rule_name': 'explicit whitelist, fail',
             'resource_name': u'fake-cluster-no-node-pools',
             'resource_data': '{"addonsConfig": {"httpLoadBalancing": {}, "istioConfig": {"auth": "AUTH_MUTUAL_TLS"}, "kubernetesDashboard": {"disabled": true}}, "name": "fake-cluster-no-node-pools", "selfLink": "fake-cluster-no-node-pools.com"}',
             'full_name': 'organization/12345/project/fake-project/kubernetes_cluster/{}/'.format(NO_NODE_POOLS_ID),
             'resource_id': NO_NODE_POOLS_ID,
             'rule_index': 1,
             'violation_type': 'KE_VIOLATION',
             'violation_data': {'violation_reason': u"name has value fake-cluster-no-node-pools, which is not in the whitelist (['real-cluster'])", 'cluster_name': u'fake-cluster-no-node-pools', 'project_id': 'fake-project', 'full_name': 'organization/12345/project/fake-project/kubernetes_cluster/{}/'.format(NO_NODE_POOLS_ID)},
             'resource_type': 'kubernetes_cluster'},

            {'rule_name': 'multiple values, pass',
             'resource_name': u'fake-cluster-no-node-pools',
             'resource_data': '{"addonsConfig": {"httpLoadBalancing": {}, "istioConfig": {"auth": "AUTH_MUTUAL_TLS"}, "kubernetesDashboard": {"disabled": true}}, "name": "fake-cluster-no-node-pools", "selfLink": "fake-cluster-no-node-pools.com"}',
             'full_name': 'organization/12345/project/fake-project/kubernetes_cluster/{}/'.format(NO_NODE_POOLS_ID),
             'resource_id': NO_NODE_POOLS_ID,
             'rule_index': 4,
             'violation_type': 'KE_VIOLATION',
             'violation_data': {'violation_reason': u"name has value fake-cluster-no-node-pools, which is not in the whitelist (['real-cluster', 'fake-cluster'])", 'cluster_name': u'fake-cluster-no-node-pools', 'project_id': 'fake-project', 'full_name': 'organization/12345/project/fake-project/kubernetes_cluster/{}/'.format(NO_NODE_POOLS_ID)},
             'resource_type': 'kubernetes_cluster'},

            {'rule_name': 'multiple values, fail',
             'resource_name': u'fake-cluster-no-node-pools',
             'resource_data': '{"addonsConfig": {"httpLoadBalancing": {}, "istioConfig": {"auth": "AUTH_MUTUAL_TLS"}, "kubernetesDashboard": {"disabled": true}}, "name": "fake-cluster-no-node-pools", "selfLink": "fake-cluster-no-node-pools.com"}',
             'full_name': 'organization/12345/project/fake-project/kubernetes_cluster/{}/'.format(NO_NODE_POOLS_ID),
             'resource_id': NO_NODE_POOLS_ID,
             'rule_index': 5,
             'violation_type': 'KE_VIOLATION',
             'violation_data': {'violation_reason': u"name has value fake-cluster-no-node-pools, which is not in the whitelist (['real-cluster', 'imaginary-cluster'])", 'cluster_name': u'fake-cluster-no-node-pools', 'project_id': 'fake-project', 'full_name': 'organization/12345/project/fake-project/kubernetes_cluster/{}/'.format(NO_NODE_POOLS_ID)},
             'resource_type': 'kubernetes_cluster'},

            {'rule_name': 'use projection to look for a list, pass',
             'resource_name': u'fake-cluster-no-node-pools',
             'resource_data': '{"addonsConfig": {"httpLoadBalancing": {}, "istioConfig": {"auth": "AUTH_MUTUAL_TLS"}, "kubernetesDashboard": {"disabled": true}}, "name": "fake-cluster-no-node-pools", "selfLink": "fake-cluster-no-node-pools.com"}',
             'full_name': 'organization/12345/project/fake-project/kubernetes_cluster/{}/'.format(NO_NODE_POOLS_ID),
             'resource_id': NO_NODE_POOLS_ID,
             'rule_index': 7, 'violation_type': 'KE_VIOLATION',
             'violation_data': {'violation_reason': "nodePools[*].config.imageType has value None, which is not in the whitelist ([['COS', 'COS']])", 'cluster_name': u'fake-cluster-no-node-pools', 'project_id': 'fake-project', 'full_name': 'organization/12345/project/fake-project/kubernetes_cluster/{}/'.format(NO_NODE_POOLS_ID)},
             'resource_type': 'kubernetes_cluster'},

            {'rule_name': 'use projection, look for a list, fail',
             'resource_name': u'fake-cluster-no-node-pools',
             'resource_data': '{"addonsConfig": {"httpLoadBalancing": {}, "istioConfig": {"auth": "AUTH_MUTUAL_TLS"}, "kubernetesDashboard": {"disabled": true}}, "name": "fake-cluster-no-node-pools", "selfLink": "fake-cluster-no-node-pools.com"}',
             'full_name': 'organization/12345/project/fake-project/kubernetes_cluster/{}/'.format(NO_NODE_POOLS_ID),
             'resource_id': NO_NODE_POOLS_ID,
             'rule_index': 8,
             'violation_type': 'KE_VIOLATION',
             'violation_data': {'violation_reason': "nodePools[*].config.imageType has value None, which is not in the whitelist ([['COS'], ['Ubuntu', 'COS']])", 'cluster_name': u'fake-cluster-no-node-pools', 'project_id': 'fake-project', 'full_name': 'organization/12345/project/fake-project/kubernetes_cluster/{}/'.format(NO_NODE_POOLS_ID)},
             'resource_type': 'kubernetes_cluster'},

            {'rule_name': 'missing nodePool, should generate violation',
             'resource_name': 'fake-cluster-no-node-pools',
             'resource_data': '{"addonsConfig": {"httpLoadBalancing": {}, "istioConfig": {"auth": "AUTH_MUTUAL_TLS"}, "kubernetesDashboard": {"disabled": true}}, "name": "fake-cluster-no-node-pools", "selfLink": "fake-cluster-no-node-pools.com"}',
             'full_name': 'organization/12345/project/fake-project/kubernetes_cluster/{}/'.format(NO_NODE_POOLS_ID),
             'resource_id': NO_NODE_POOLS_ID,
             'rule_index': 12,
             'violation_type': 'KE_VIOLATION',
             'violation_data': {'violation_reason': 'length(nodePools || `[]`) > `0` has value False, which is not in the whitelist ([True])',
                                'cluster_name': 'fake-cluster-no-node-pools',
                                'project_id': 'fake-project',
                                'full_name': 'organization/12345/project/fake-project/kubernetes_cluster/{}/'.format(NO_NODE_POOLS_ID)},
             'resource_type': 'kubernetes_cluster'},

            {'rule_name': 'explicit whitelist, fail',
             'resource_name': u'fake-cluster',
             'full_name': u'organization/12345/project/fake-project/kubernetes_cluster/{}/'.format(FAKE_CLUSTER_ID),
             'resource_data': '{"addonsConfig": {"httpLoadBalancing": {}, "istioConfig": {"auth": "AUTH_MUTUAL_TLS"}, "kubernetesDashboard": {"disabled": true}}, "name": "fake-cluster", "nodePools": [{"config": {"imageType": "COS"}, "name": "default-pool", "version": "1.7.11-gke.1"}, {"config": {"imageType": "COS"}, "name": "secondary-pool", "version": "1.7.11-gke.1"}], "selfLink": "fake-cluster.com"}',
             'resource_id': FAKE_CLUSTER_ID,
             'rule_index': 1,
             'violation_type': 'KE_VIOLATION',
             'violation_data': {'violation_reason': u"name has value fake-cluster, which is not in the whitelist (['real-cluster'])", 'cluster_name': u'fake-cluster', 'project_id': 'fake-project', 'full_name': 'organization/12345/project/fake-project/kubernetes_cluster/{}/'.format(FAKE_CLUSTER_ID)},
             'resource_type': 'kubernetes_cluster'},
            {'rule_name': 'explicit blacklist, fail',
             'resource_name': u'fake-cluster',
             'resource_data': '{"addonsConfig": {"httpLoadBalancing": {}, "istioConfig": {"auth": "AUTH_MUTUAL_TLS"}, "kubernetesDashboard": {"disabled": true}}, "name": "fake-cluster", "nodePools": [{"config": {"imageType": "COS"}, "name": "default-pool", "version": "1.7.11-gke.1"}, {"config": {"imageType": "COS"}, "name": "secondary-pool", "version": "1.7.11-gke.1"}], "selfLink": "fake-cluster.com"}',
             'full_name': u'organization/12345/project/fake-project/kubernetes_cluster/{}/'.format(FAKE_CLUSTER_ID),
             'resource_id': FAKE_CLUSTER_ID,
             'rule_index': 3,
             'violation_type': 'KE_VIOLATION',
             'violation_data': {'violation_reason': u"name has value fake-cluster, which is in the blacklist (['fake-cluster'])", 'cluster_name': u'fake-cluster', 'project_id': 'fake-project', 'full_name': 'organization/12345/project/fake-project/kubernetes_cluster/{}/'.format(FAKE_CLUSTER_ID)},
             'resource_type': 'kubernetes_cluster'},
            {'rule_name': 'multiple values, fail',
             'resource_name': u'fake-cluster',
             'resource_data': '{"addonsConfig": {"httpLoadBalancing": {}, "istioConfig": {"auth": "AUTH_MUTUAL_TLS"}, "kubernetesDashboard": {"disabled": true}}, "name": "fake-cluster", "nodePools": [{"config": {"imageType": "COS"}, "name": "default-pool", "version": "1.7.11-gke.1"}, {"config": {"imageType": "COS"}, "name": "secondary-pool", "version": "1.7.11-gke.1"}], "selfLink": "fake-cluster.com"}',
             'full_name': u'organization/12345/project/fake-project/kubernetes_cluster/{}/'.format(FAKE_CLUSTER_ID), 'resource_id': FAKE_CLUSTER_ID, 'rule_index': 5, 'violation_type': 'KE_VIOLATION', 'violation_data': {'violation_reason': u"name has value fake-cluster, which is not in the whitelist (['real-cluster', 'imaginary-cluster'])", 'cluster_name': u'fake-cluster', 'project_id': 'fake-project', 'full_name': 'organization/12345/project/fake-project/kubernetes_cluster/{}/'.format(FAKE_CLUSTER_ID)}, 'resource_type': 'kubernetes_cluster'},
            {'rule_name': 'use projection, look for a list, fail',
             'resource_name': u'fake-cluster',
             'resource_data': '{"addonsConfig": {"httpLoadBalancing": {}, "istioConfig": {"auth": "AUTH_MUTUAL_TLS"}, "kubernetesDashboard": {"disabled": true}}, "name": "fake-cluster", "nodePools": [{"config": {"imageType": "COS"}, "name": "default-pool", "version": "1.7.11-gke.1"}, {"config": {"imageType": "COS"}, "name": "secondary-pool", "version": "1.7.11-gke.1"}], "selfLink": "fake-cluster.com"}',
             'full_name': u'organization/12345/project/fake-project/kubernetes_cluster/{}/'.format(FAKE_CLUSTER_ID), 'resource_id': FAKE_CLUSTER_ID, 'rule_index': 8, 'violation_type': 'KE_VIOLATION', 'violation_data': {'violation_reason': "nodePools[*].config.imageType has value [u'COS', u'COS'], which is not in the whitelist ([['COS'], ['Ubuntu', 'COS']])", 'cluster_name': u'fake-cluster', 'project_id': 'fake-project', 'full_name': 'organization/12345/project/fake-project/kubernetes_cluster/{}/'.format(FAKE_CLUSTER_ID)}, 'resource_type': 'kubernetes_cluster'},
        ]

        mock_output_results.assert_called_once_with(mock.ANY,
                                                    expected_violations)

        # check that the "missing nodePool, should not generate
        # violation" rule test case did in fact log
        self.assertTrue(mock_logger.warning.called)
        self.assertTrue(
            'JMESPath error processing KE cluster %s:' in mock_logger.warning.call_args[0][0],
        )
        self.assertTrue(NO_NODE_POOLS_ID in mock_logger.warning.call_args[0][1])


if __name__ == '__main__':
    unittest.main()
