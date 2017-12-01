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

"""IAP scanner test"""

from datetime import datetime
import json
import mock

import unittest
import yaml

from google.cloud.forseti.common.gcp_type import backend_service as backend_service_type
from google.cloud.forseti.common.gcp_type import firewall_rule as firewall_rule_type
from google.cloud.forseti.common.gcp_type import instance_group as instance_group_type
from google.cloud.forseti.common.gcp_type import instance_group_manager as instance_group_manager_type
from google.cloud.forseti.common.gcp_type import instance as instance_type
from google.cloud.forseti.common.gcp_type import instance_template as instance_template_type
from google.cloud.forseti.common.gcp_type import project as project_type
from google.cloud.forseti.common.gcp_type import network as network_type
from google.cloud.forseti.scanner.scanners import iap_scanner
from tests.unittest_utils import ForsetiTestCase
from tests.unittest_utils import get_datafile_path


class FakeProjectDao(object):

    def get_project(self, project_id, snapshot_timestamp=0):
        return project_type.Project(project_id=project_id)


class FakeOrgDao(object):

    def find_ancestors(self, resource_id, snapshot_timestamp=0):
        return []


class IapScannerTest(ForsetiTestCase):

    def network_port(self, port_number, project='foo', network='default'):
        return iap_scanner.NetworkPort(
            network=network_type.Key.from_args(project_id=project,
                                               name=network),
            port=port_number)

    def tearDown(self):
        self.org_patcher.stop()
        self.project_patcher.stop()

    def setUp(self):
        self.fake_utcnow = datetime(
            year=1900, month=1, day=1, hour=0, minute=0, second=0,
            microsecond=0)

        # patch the daos
        self.org_patcher = mock.patch(
            'google.cloud.forseti.common.data_access.'
            'org_resource_rel_dao.OrgResourceRelDao')
        self.mock_org_rel_dao = self.org_patcher.start()
        self.mock_org_rel_dao.return_value = FakeOrgDao()

        self.project_patcher = mock.patch(
            'google.cloud.forseti.common.data_access.'
            'project_dao.ProjectDao')
        self.mock_project_dao = self.project_patcher.start()
        self.mock_project_dao.return_value = FakeProjectDao()

        self.fake_scanner_configs = {'output_path': 'gs://fake/output/path'}
        self.scanner = iap_scanner.IapScanner(
            {}, {}, '',
            get_datafile_path(__file__, 'iap_scanner_test_data.yaml'))
        self.scanner.scanner_configs = self.fake_scanner_configs
        self.scanner._get_backend_services = lambda: self.backend_services.values()
        self.scanner._get_firewall_rules = lambda: self.firewall_rules.values()
        self.scanner._get_instances = lambda: self.instances.values()
        self.scanner._get_instance_groups = lambda: self.instance_groups.values()
        self.scanner._get_instance_group_managers = lambda: self.instance_group_managers.values()
        self.scanner._get_instance_templates = lambda: self.instance_templates.values()

        self.backend_services = {
            # The main backend service.
            'bs1': backend_service_type.BackendService(
                project_id='foo',
                name='bs1',
                backends=json.dumps(
                    [{'group': ('https://www.googleapis.com/compute/v1/'
                                'projects/foo/regions/wl-redqueen1/'
                                'instanceGroups/ig_managed')},
                     {'group': ('https://www.googleapis.com/compute/v1/'
                                'projects/foo/regions/wl-redqueen1/'
                                'instanceGroups/ig_unmanaged')},
                    ]),
                iap=json.dumps({'enabled': True}),
                port=80,
                port_name='http',
                ),
            # Another backend service that connects to the same backend.
            'bs1_same_backend': backend_service_type.BackendService(
                project_id='foo',
                name='bs1_same_backend',
                backends=json.dumps(
                    [{'group': ('https://www.googleapis.com/compute/v1/'
                                'projects/foo/regions/wl-redqueen1/'
                                'instanceGroups/ig_managed')},
                    ]),
                port=80,
                ),
            # A backend service with a different port (so, not an alternate).
            'bs1_different_port': backend_service_type.BackendService(
                project_id='foo',
                name='bs1_different_port',
                backends=json.dumps(
                    [{'group': ('https://www.googleapis.com/compute/v1/'
                                'projects/foo/regions/wl-redqueen1/'
                                'instanceGroups/ig_managed')},
                    ]),
                port=81,
                ),
            # Various backend services that should or shouldn't be alts.
            'bs1_same_instance': backend_service_type.BackendService(
                project_id='foo',
                name='bs1_same_instance',
                backends=json.dumps(
                    [{'group': ('https://www.googleapis.com/compute/v1/'
                                'projects/foo/regions/wl-redqueen1/'
                                'instanceGroups/ig_same_instance')},
                    ]),
                port=80,
                ),
            'bs1_different_network': backend_service_type.BackendService(
                project_id='foo',
                name='bs1_different_network',
                backends=json.dumps(
                    [{'group': ('https://www.googleapis.com/compute/v1/'
                                'projects/foo/regions/wl-redqueen1/'
                                'instanceGroups/ig_different_network')},
                    ]),
                port=80,
                ),
            'bs1_different_instance': backend_service_type.BackendService(
                project_id='foo',
                name='bs1_different_instance',
                backends=json.dumps(
                    [{'group': ('https://www.googleapis.com/compute/v1/'
                                'projects/foo/regions/wl-redqueen1/'
                                'instanceGroups/ig_different_instance')},
                    ]),
                port=80,
                ),
        }
        self.firewall_rules = {
            # Doesn't apply because of IPProtocol mismatch.
            'proto_mismatch': firewall_rule_type.FirewallRule(
                project_id='foo',
                firewall_rule_name='proto_mismatch',
                firewall_rule_network='global/networks/default',
                firewall_rule_source_tags=json.dumps(['proto_mismatch']),
                firewall_rule_allowed=json.dumps([{
                    'IPProtocol': 'udp',
                }]),
            ),
            # Preempted by allow.
            'deny_applies_all_preempted': firewall_rule_type.FirewallRule(
                project_id='foo',
                firewall_rule_name='deny_applies_all_preempted',
                firewall_rule_priority=60000,
                firewall_rule_network='global/networks/default',
                firewall_rule_source_ranges=json.dumps(['applies_all']),
                firewall_rule_denied=json.dumps([{
                    'IPProtocol': 'tcp',
                }]),
            ),
            # Applies to all ports, tags.
            'applies_all': firewall_rule_type.FirewallRule(
                project_id='foo',
                firewall_rule_name='applies_all',
                firewall_rule_network='global/networks/default',
                firewall_rule_source_ranges=json.dumps(['10.0.2.0/24']),
                firewall_rule_source_tags=json.dumps(['applies_all']),
                firewall_rule_allowed=json.dumps([{
                    'IPProtocol': 'tcp',
                }]),
            ),
            # Applies to only port 8080.
            'applies_8080': firewall_rule_type.FirewallRule(
                project_id='foo',
                firewall_rule_name='applies_8080',
                firewall_rule_network='global/networks/default',
                firewall_rule_source_tags=json.dumps(['applies_8080']),
                firewall_rule_allowed=json.dumps([{
                    'IPProtocol': 'tcp',
                    'ports': [8080],
                }]),
            ),
            # Applies to a multi-port range.
            'applies_8081_8083': firewall_rule_type.FirewallRule(
                project_id='foo',
                firewall_rule_name='applies_8081_8083',
                firewall_rule_network='global/networks/default',
                firewall_rule_source_tags=json.dumps(['applies_8081_8083']),
                firewall_rule_allowed=json.dumps([{
                    'IPProtocol': 'tcp',
                    'ports': ['8081-8083'],
                }]),
            ),
            # Doesn't apply because of direction mismatch.
            'direction': firewall_rule_type.FirewallRule(
                project_id='foo',
                firewall_rule_name='direction',
                firewall_rule_direction='EGRESS',
                firewall_rule_network='global/networks/default',
                firewall_rule_source_tags=json.dumps(['direction']),
                firewall_rule_allowed=json.dumps([{
                    'IPProtocol': 'tcp',
                }]),
            ),
            # Doesn't apply because of network mismatch.
            'network': firewall_rule_type.FirewallRule(
                project_id='foo',
                firewall_rule_name='network',
                firewall_rule_network='global/networks/social',
                firewall_rule_source_tags=json.dumps(['network']),
                firewall_rule_allowed=json.dumps([{
                    'IPProtocol': 'tcp',
                }]),
            ),
            # Doesn't apply because of tags.
            'tag_mismatch': firewall_rule_type.FirewallRule(
                project_id='foo',
                firewall_rule_name='tag_mismatch',
                firewall_rule_network='global/networks/default',
                firewall_rule_source_tags=json.dumps(['tag_mismatch']),
                firewall_rule_target_tags=json.dumps(['im_gonna_pop_some_tags']),
                firewall_rule_allowed=json.dumps([{
                    'IPProtocol': 'tcp',
                }]),
            ),
            # Tag-specific rule *does* apply.
            'tag_match': firewall_rule_type.FirewallRule(
                project_id='foo',
                firewall_rule_name='tag_match',
                firewall_rule_network='global/networks/default',
                firewall_rule_source_tags=json.dumps(['tag_match']),
                firewall_rule_target_tags=json.dumps(['tag_i1']),
                firewall_rule_allowed=json.dumps([{
                    'IPProtocol': 'tcp',
                }]),
            ),
            # Preempted by deny rule.
            'preempted': firewall_rule_type.FirewallRule(
                project_id='foo',
                firewall_rule_name='preempted',
                firewall_rule_network='global/networks/default',
                firewall_rule_source_tags=json.dumps(['preempted']),
                firewall_rule_allowed=json.dumps([{
                    'IPProtocol': 'tcp',
                }]),
            ),
            # Preempted by deny rule.
            'preempted_deny': firewall_rule_type.FirewallRule(
                project_id='foo',
                firewall_rule_name='preempted_deny',
                firewall_rule_priority=1,
                firewall_rule_network='global/networks/default',
                firewall_rule_source_ranges=json.dumps(['preempted']),
                firewall_rule_denied=json.dumps([{
                    'IPProtocol': 'tcp',
                }]),
            ),
        }
        self.instances = {
            'i1': instance_type.Instance(
                project_id='foo',
                name='i1',
                tags=json.dumps({'items': ['tag_i1']}),
                zone='wl-redqueen1-a',
            ),
            'i2': instance_type.Instance(
                project_id='foo',
                name='i2',
                tags=json.dumps([]),
                zone='wl-redqueen1-a',
            ),
        }
        self.instance_groups = {
            # Managed
            'ig_managed': instance_group_type.InstanceGroup(
                project_id='foo',
                name='ig_managed',
                network='global/networks/default',
                region='wl-redqueen1',
                instance_urls=json.dumps(
                    [('https://www.googleapis.com/compute/v1/'
                      'projects/foo/zones/wl-redqueen1-a/instances/i1')]),
            ),
            # Unmanaged; overrides port mapping
            'ig_unmanaged': instance_group_type.InstanceGroup(
                project_id='foo',
                name='ig_unmanaged',
                network='global/networks/default',
                region='wl-redqueen1',
                instance_urls=json.dumps([]),
                named_ports=json.dumps(
                    [{'name': 'foo', 'port': 80},
                     {'name': 'http', 'port': 8080}]),
            ),
            # Unmanaged; same instance as ig_managed
            'ig_same_instance': instance_group_type.InstanceGroup(
                project_id='foo',
                name='ig_same_instance',
                network='global/networks/default',
                region='wl-redqueen1',
                instance_urls=json.dumps(
                    [('https://www.googleapis.com/compute/v1/'
                      'projects/foo/zones/wl-redqueen1-a/instances/i1')]),
            ),
            # Unmanaged; different network than ig_managed
            'ig_different_network': instance_group_type.InstanceGroup(
                project_id='foo',
                name='ig_different_network',
                network='global/networks/nondefault',
                region='wl-redqueen1',
                instance_urls=json.dumps(
                    [('https://www.googleapis.com/compute/v1/'
                      'projects/foo/zones/wl-redqueen1-a/instances/i1')]),
            ),
            # Unmanaged; different instance than ig_managed
            'ig_different_instance': instance_group_type.InstanceGroup(
                project_id='foo',
                name='ig5',
                network='global/networks/default',
                region='wl-redqueen1',
                instance_urls=json.dumps(
                    [('https://www.googleapis.com/compute/v1/'
                      'projects/foo/zones/wl-redqueen1-a/instances/i2')]),
            ),
        }
        self.instance_group_managers = {
            'igm1': instance_group_manager_type.InstanceGroupManager(
                project_id='foo',
                name='igm1',
                instance_group=('https://www.googleapis.com/compute/v1/'
                                'projects/foo/regions/wl-redqueen1/instanceGroups/ig_managed'),
                instance_template=('https://www.googleapis.com/compute/v1/'
                                   'projects/foo/global/instanceTemplates/it1'),
                region='wl-redqueen1',
            ),
        }
        self.instance_templates = {
            'it1': instance_template_type.InstanceTemplate(
                project_id='foo',
                name='it1',
                properties=json.dumps({
                    'tags': {'items': ['tag_it1']},
                }),
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
                self.instance_groups['ig_managed'].key: self.instance_templates['it1'],
            },
            self.data.instance_templates_by_group_key)

    def test_find_instance_group(self):
        self.assertEqual(self.instance_groups['ig_managed'],
                         self.data.find_instance_group_by_url(
                             'https://www.googleapis.com/compute/v1/'
                             'projects/foo/regions/wl-redqueen1/instanceGroups/ig_managed'))

    def test_find_instance(self):
        self.assertEqual(self.instances['i1'],
                         self.data.find_instance_by_url(
                             'https://www.googleapis.com/compute/v1/'
                             'projects/foo/zones/wl-redqueen1-a/instances/i1'))

    def test_find_network_port(self):
        self.assertEqual(
            self.network_port(80),
            self.data.instance_group_network_port(
                self.backend_services['bs1'], self.instance_groups['ig_managed']))

        # ig_unmanaged overrides port mapping, so it gets a different port number
        self.assertEqual(
            self.network_port(8080),
            self.data.instance_group_network_port(
                self.backend_services['bs1'], self.instance_groups['ig_unmanaged']))

    def test_firewall_allowed_sources(self):
        self.assertEqual(
            set(['10.0.2.0/24', 'tag_match', 'applies_all']),
            self.data.firewall_allowed_sources(self.network_port(80), 'tag_i1'))
        self.assertEqual(
            set(['10.0.2.0/24', 'tag_match', 'applies_all']),
            self.data.firewall_allowed_sources(self.network_port(81), 'tag_i1'))
        self.assertEqual(
            set(['10.0.2.0/24', 'applies_all']),
            self.data.firewall_allowed_sources(self.network_port(80), 'tag'))
        self.assertEqual(
            set(['10.0.2.0/24', 'applies_all']),
            self.data.firewall_allowed_sources(self.network_port(8079), 'tag'))
        self.assertEqual(
            set(['10.0.2.0/24', 'applies_all', 'applies_8080']),
            self.data.firewall_allowed_sources(self.network_port(8080), 'tag'))
        self.assertEqual(
            set(['10.0.2.0/24', 'applies_all', 'applies_8081_8083']),
            self.data.firewall_allowed_sources(self.network_port(8081), 'tag'))
        self.assertEqual(
            set(['10.0.2.0/24', 'applies_all', 'applies_8081_8083']),
            self.data.firewall_allowed_sources(self.network_port(8082), 'tag'))
        self.assertEqual(
            set(['10.0.2.0/24', 'applies_all', 'applies_8081_8083']),
            self.data.firewall_allowed_sources(self.network_port(8083), 'tag'))
        self.assertEqual(
            set(['10.0.2.0/24', 'applies_all']),
            self.data.firewall_allowed_sources(self.network_port(8084), 'tag'))

    def test_tags_for_instance_group(self):
        self.assertEqual(
            set(['tag_i1', 'tag_it1']),
            self.data.tags_for_instance_group(self.instance_groups['ig_managed']))
        self.assertEqual(
            set(),
            self.data.tags_for_instance_group(self.instance_groups['ig_unmanaged']))

    def test_retrieve_resources(self):
        iap_resources = dict((resource.backend_service.key, resource)
                             for resource in self.scanner._retrieve()[0])
        self.maxDiff = None
        self.assertEquals(set([bs.key for bs in self.backend_services.values()]),
                          set(iap_resources.keys()))
        self.assertEquals(
            iap_scanner.IapResource(
                backend_service=self.backend_services['bs1'],
                alternate_services=set([
                    backend_service_type.Key.from_args(
                        project_id='foo',
                        name='bs1_same_backend',
                    ),
                    backend_service_type.Key.from_args(
                        project_id='foo',
                        name='bs1_same_instance',
                    ),
                ]),
                direct_access_sources=set(['10.0.2.0/24',
                                           'tag_match',
                                           'applies_all',
                                           'applies_8080']),
                iap_enabled=True,
            ),
            iap_resources[self.backend_services['bs1'].key])

    @mock.patch(
        'google.cloud.forseti.scanner.scanners.iap_scanner.datetime',
        autospec=True)
    @mock.patch(
        'google.cloud.forseti.scanner.scanners.iap_scanner.notifier',
        autospec=True)
    @mock.patch.object(
        iap_scanner.IapScanner,
        '_upload_csv', autospec=True)
    @mock.patch.object(
        iap_scanner.csv_writer,
        'write_csv', autospec=True)
    @mock.patch.object(
        iap_scanner.IapScanner,
        '_output_results_to_db', autospec=True)
    def test_run_scanner(self, mock_output_results, mock_csv_writer,
                         mock_upload_csv, mock_notifier, mock_datetime):
        mock_datetime.utcnow = mock.MagicMock()
        mock_datetime.utcnow.return_value = self.fake_utcnow

        fake_csv_name = 'fake.csv'
        fake_csv_file = type(
            mock_csv_writer.return_value.__enter__.return_value)
        fake_csv_file.name = fake_csv_name

        self.scanner.run()
        self.assertEquals(1, mock_output_results.call_count)
        mock_upload_csv.assert_called_once_with(
            self.scanner,
            self.fake_scanner_configs.get('output_path'),
            self.fake_utcnow,
            fake_csv_name)
        mock_csv_writer.assert_called_once_with(
            data=[{'resource_id': None,
                   'rule_name': 'test',
                   'rule_index': 0,
                   'violation_data': {
                       'iap_enabled_violation': 'True',
                       'resource_name': 'bs1_different_port',
                       'alternate_services_violations': '',
                       'direct_access_sources_violations': ''},
                   'violation_type': 'IAP_VIOLATION',
                   'resource_type': 'backend_service'},
                  {'resource_id': None,
                   'rule_name': 'test',
                   'rule_index': 0,
                   'violation_data': {
                       'iap_enabled_violation': 'True',
                       'resource_name': 'bs1_different_network',
                       'alternate_services_violations': '',
                       'direct_access_sources_violations': ''},
                   'violation_type': 'IAP_VIOLATION',
                   'resource_type': 'backend_service'},
                  {'resource_id': None,
                   'rule_name': 'test',
                   'rule_index': 0,
                   'violation_data': {
                       'iap_enabled_violation': 'False',
                       'resource_name': 'bs1',
                       'alternate_services_violations': (
                           'foo/bs1_same_backend, foo/bs1_same_instance'),
                       'direct_access_sources_violations': (
                           '10.0.2.0/24, '
                           'applies_8080, '
                           'applies_all, '
                           'tag_match')},
                   'violation_type': 'IAP_VIOLATION',
                   'resource_type': 'backend_service'},
                  {'resource_id': None,
                   'rule_name': 'test',
                   'rule_index': 0,
                   'violation_data': {
                       'iap_enabled_violation': 'True',
                       'resource_name': 'bs1_different_instance',
                       'alternate_services_violations': '',
                       'direct_access_sources_violations': ''},
                   'violation_type': 'IAP_VIOLATION',
                   'resource_type': 'backend_service'},
                  {'resource_id': None,
                   'rule_name': 'test',
                   'rule_index': 0,
                   'violation_data': {
                       'iap_enabled_violation': 'True',
                       'resource_name': 'bs1_same_backend',
                       'alternate_services_violations': '',
                       'direct_access_sources_violations': ''},
                   'violation_type': 'IAP_VIOLATION',
                   'resource_type': 'backend_service'},
                  {'resource_id': None,
                   'rule_name': 'test',
                   'rule_index': 0,
                   'violation_data': {
                       'iap_enabled_violation': 'True',
                       'resource_name': 'bs1_same_instance',
                       'alternate_services_violations': '',
                       'direct_access_sources_violations': ''},
                   'violation_type': 'IAP_VIOLATION',
                   'resource_type': 'backend_service'}],
            resource_name='violations',
            write_header=True)
        self.assertEquals(0, mock_notifier.process.call_count)


if __name__ == '__main__':
    unittest.main()
