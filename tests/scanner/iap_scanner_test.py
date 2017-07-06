# Copyright 2017 Google Inc.
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

"""IAP scanner test"""

import mock

import yaml

from google.cloud.security.common.gcp_type import backend_service as backend_service_type
from google.cloud.security.common.gcp_type import firewall_rule as firewall_rule_type
from google.cloud.security.common.gcp_type import instance_group as instance_group_type
from google.cloud.security.common.gcp_type import instance_group_manager as instance_group_manager_type
from google.cloud.security.common.gcp_type import instance as instance_type
from google.cloud.security.common.gcp_type import instance_template as instance_template_type
from google.cloud.security.common.gcp_type import network as network_type
from google.cloud.security.scanner.scanners import iap_scanner
from tests.unittest_utils import ForsetiTestCase
#from tests.scanner.test_data import fake_iap_scanner_data as fake_data



class RunDataTest(ForsetiTestCase):

    def setUp(self):
        self.backend_services = {
            'bs1': backend_service_type.BackendService(
                project_id='foo',
                name='bs1',
                backends={'group': ('https://www.googleapis.com/compute/v1/'
                                    'projects/foo/regions/wl-redqueen1/'
                                    'instanceGroups/ig1')},
                iap={'enabled': True},
                port=80,
                port_name='http',
                ),
        }
        self.firewall_rules = {
            'fw1': firewall_rule_type.FirewallRule(
                project_id='foo',
                firewall_rule_name='fw1',
                firewall_rule_network='global/networks/default',
                firewall_rule_source_ranges=['0.0.0.0/0'],
                firewall_rule_allowed=[{
                    'IPProtocol': 'tcp',
                }],
            ),
        }
        self.instances = {
            'i1': instance_type.Instance(
                project_id='foo',
                name='i1',
                tags=[],
                zone='wl-redqueen1-a',
            ),
        }
        self.instance_groups = {
            'ig1': instance_group_type.InstanceGroup(
                project_id='foo',
                name='ig1',
                network='global/networks/default',
                region='wl-redqueen1',
                instance_urls=[('https://www.googleapis.com/compute/v1/'
                                'projects/foo/zones/wl-redqueen1-a/instances/i1')],
            ),
        }
        self.instance_group_managers = {
            'igm1': instance_group_manager_type.InstanceGroupManager(
                project_id='foo',
                name='igm1',
                instance_group=('https://www.googleapis.com/compute/v1/'
                                'projects/foo/regions/wl-redqueen1/instanceGroups/ig1'),
                instance_template=('https://www.googleapis.com/compute/v1/'
                                   'projects/foo/global/instanceTemplates/it1'),
                region='wl-redqueen1',
            ),
        }
        self.instance_templates = {
            'it1': instance_template_type.InstanceTemplate(
                project_id='foo',
                name='it1',
                properties={},
            ),
        }
        self.data = iap_scanner._RunData(self.backend_services.values(),
                                         self.firewall_rules.values(),
                                         self.instances.values(),
                                         self.instance_groups.values(),
                                         self.instance_group_managers.values(),
                                         self.instance_templates.values(),
                                         )

    def test_instance_template_map(self):
        self.assertEqual(
            {
                self.instance_groups['ig1'].key: self.instance_templates['it1'],
            },
            self.data.instance_templates_by_instance_group_key)

    def test_find_instance_group(self):
        self.assertEqual(self.instance_groups['ig1'],
                         self.data.find_instance_group_by_url(
                             'https://www.googleapis.com/compute/v1/'
                             'projects/foo/regions/wl-redqueen1/instanceGroups/ig1'))

    def test_find_instance(self):
        self.assertEqual(self.instances['i1'],
                         self.data.find_instance_by_url(
                             'https://www.googleapis.com/compute/v1/'
                             'projects/foo/zones/wl-redqueen1-a/instances/i1'))

    def test_find_network_port(self):
        self.assertEqual(
            iap_scanner.NetworkPort(
                network=network_type.Key.from_args(project_id='foo',
                                                   name='default'),
                port=80),
            self.data.instance_group_network_port(
                self.backend_services['bs1'], self.instance_groups['ig1']))

    def test_firewall_allowed_sources(self):
        self.assertEqual(
            set(['0.0.0.0/0']),
            self.data.firewall_allowed_sources(
                iap_scanner.NetworkPort(
                    network=network_type.Key.from_args(project_id='foo',
                                                       name='default'),
                    port=80),
                'tag1'))

    def test_tags_for_instance_group(self):
        self.assertEqual(
            set(),
            self.data.tags_for_instance_group(self.instance_groups['ig1']))


if __name__ == '__main__':
    unittest.main()
