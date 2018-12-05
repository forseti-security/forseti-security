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
"""IAP scanner test."""

from datetime import datetime
import json
import unittest
import mock

from tests.services.util.db import create_test_engine
from tests.unittest_utils import ForsetiTestCase
from tests.unittest_utils import get_datafile_path
from google.cloud.forseti.common.gcp_type import backend_service as backend_service_type
from google.cloud.forseti.common.gcp_type import firewall_rule as firewall_rule_type
from google.cloud.forseti.common.gcp_type import instance as instance_type
from google.cloud.forseti.common.gcp_type import instance_group as instance_group_type
from google.cloud.forseti.common.gcp_type import instance_group_manager as instance_group_manager_type
from google.cloud.forseti.common.gcp_type import instance_template as instance_template_type
from google.cloud.forseti.common.gcp_type import project as project_type
from google.cloud.forseti.common.gcp_type import network as network_type
from google.cloud.forseti.scanner.scanners import base_scanner
from google.cloud.forseti.scanner.scanners import iap_scanner
from google.cloud.forseti.services.dao import ModelManager

# pylint: disable=bad-indentation
BACKEND_SERVICES = {
    # The main backend service.
    'bs1':
        backend_service_type.BackendService(
            project_id='foo',
            name='bs1',
            backends=[{
                'group': ('https://www.googleapis.com/compute/v1/'
                          'projects/foo/regions/wl-redqueen1/'
                          'instanceGroups/ig_managed')
            }, {
                'group': ('https://www.googleapis.com/compute/v1/'
                          'projects/foo/regions/wl-redqueen1/'
                          'instanceGroups/ig_unmanaged')
            }],
            iap={'enabled': True},
            port=80,
            port_name='http',
        ),
    # Another backend service that connects to the same backend.
    'bs1_same_backend':
        backend_service_type.BackendService(
            project_id='foo',
            name='bs1_same_backend',
            backends=[{
                'group': ('https://www.googleapis.com/compute/v1/'
                          'projects/foo/regions/wl-redqueen1/'
                          'instanceGroups/ig_managed')
            }],
            port=80,
        ),
    # A backend service with a different port (so, not an alternate).
    'bs1_different_port':
        backend_service_type.BackendService(
            project_id='foo',
            name='bs1_different_port',
            backends=[{
                'group': ('https://www.googleapis.com/compute/v1/'
                          'projects/foo/regions/wl-redqueen1/'
                          'instanceGroups/ig_managed')
            }],
            port=81,
        ),
    # Various backend services that should or shouldn't be alts.
    'bs1_same_instance':
        backend_service_type.BackendService(
            project_id='foo',
            name='bs1_same_instance',
            backends=[{
                'group': ('https://www.googleapis.com/compute/v1/'
                          'projects/foo/regions/wl-redqueen1/'
                          'instanceGroups/ig_same_instance')
            }],
            port=80,
        ),
    'bs1_different_network':
        backend_service_type.BackendService(
            project_id='foo',
            name='bs1_different_network',
            backends=[{
                'group': ('https://www.googleapis.com/compute/v1/'
                          'projects/foo/regions/wl-redqueen1/'
                          'instanceGroups/ig_different_network')
            }],
            port=80,
        ),
    'bs1_different_instance':
        backend_service_type.BackendService(
            project_id='foo',
            name='bs1_different_instance',
            backends=[{
                'group': ('https://www.googleapis.com/compute/v1/'
                          'projects/foo/regions/wl-redqueen1/'
                          'instanceGroups/ig_different_instance')
            }],
            port=80,
        ),
}
FIREWALL_RULES = {
    # Doesn't apply because of IPProtocol mismatch.
    'proto_mismatch':
        firewall_rule_type.FirewallRule(
            project_id='foo',
            firewall_rule_name='proto_mismatch',
            firewall_rule_network='global/networks/default',
            firewall_rule_source_tags=json.dumps(['proto_mismatch']),
            firewall_rule_allowed=json.dumps([{
                'IPProtocol': 'udp',
            }]),
        ),
    # Preempted by allow.
    'deny_applies_all_preempted':
        firewall_rule_type.FirewallRule(
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
    'applies_all':
        firewall_rule_type.FirewallRule(
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
    'applies_8080':
        firewall_rule_type.FirewallRule(
            project_id='foo',
            firewall_rule_name='applies_8080',
            firewall_rule_network='global/networks/default',
            firewall_rule_source_tags=json.dumps(['applies_8080']),
            firewall_rule_allowed=json.dumps([{
                'IPProtocol': 'tcp',
                'ports': ['8080'],
            }]),
        ),
    # Applies to a multi-port range.
    'applies_8081_8083':
        firewall_rule_type.FirewallRule(
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
    'direction':
        firewall_rule_type.FirewallRule(
            project_id='foo',
            firewall_rule_name='direction',
            firewall_rule_direction='EGRESS',
            firewall_rule_network='global/networks/default',
            firewall_rule_target_tags=json.dumps(['direction']),
            firewall_rule_destination_ranges=json.dumps(['0.0.0.0/0']),
            firewall_rule_allowed=json.dumps([{
                'IPProtocol': 'tcp',
            }]),
        ),
    # Doesn't apply because of network mismatch.
    'network':
        firewall_rule_type.FirewallRule(
            project_id='foo',
            firewall_rule_name='network',
            firewall_rule_network='global/networks/social',
            firewall_rule_source_tags=json.dumps(['network']),
            firewall_rule_allowed=json.dumps([{
                'IPProtocol': 'tcp',
            }]),
        ),
    # Doesn't apply because of tags.
    'tag_mismatch':
        firewall_rule_type.FirewallRule(
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
    'tag_match':
        firewall_rule_type.FirewallRule(
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
    'preempted':
        firewall_rule_type.FirewallRule(
            project_id='foo',
            firewall_rule_name='preempted',
            firewall_rule_network='global/networks/default',
            firewall_rule_source_tags=json.dumps(['preempted']),
            firewall_rule_allowed=json.dumps([{
                'IPProtocol': 'tcp',
            }]),
        ),
    # Preempted by deny rule.
    'preempted_deny':
        firewall_rule_type.FirewallRule(
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
PROJECTS = {
    'foo': project_type.Project(project_id='foo'),
}
INSTANCES = {
    'i1':
        instance_type.Instance(
            'i1',
            parent=PROJECTS['foo'],
            name='i1',
            tags={'items': ['tag_i1']},
            locations=['wl-redqueen1-a'],
            data = ("""{
    "name": "i2",
    "selfLink": "https://www.googleapis.com/compute/v1/projects/foo/zones/wl-redqueen1-a/instances/i1",
    "tags": {"items": ["tag_i1"]}
}""")
        ),
    'i2':
        instance_type.Instance(
            'i2',
            parent=PROJECTS['foo'],
            name='i2',
            tags=[],
            locations=['wl-redqueen1-a'],
            data = ("""{
    "name": "i2",
    "selfLink": "https://www.googleapis.com/compute/v1/projects/foo/zones/wl-redqueen1-a/instances/i2",
    "tags": {}
}""")
        ),
}
INSTANCE_GROUPS = {
    # Managed
    'ig_managed':
        instance_group_type.InstanceGroup(
            project_id='foo',
            name='ig_managed',
            network='global/networks/default',
            region='wl-redqueen1',
            instance_urls=[('https://www.googleapis.com/compute/v1/'
                            'projects/foo/zones/wl-redqueen1-a/instances/i1')],
        ),
    # Unmanaged; overrides port mapping
    'ig_unmanaged':
        instance_group_type.InstanceGroup(
            project_id='foo',
            name='ig_unmanaged',
            network='global/networks/default',
            region='wl-redqueen1',
            instance_urls=[],
            named_ports=[{
                'name': 'foo',
                'port': 80
            }, {
                'name': 'http',
                'port': 8080
            }],
        ),
    # Unmanaged; same instance as ig_managed
    'ig_same_instance':
        instance_group_type.InstanceGroup(
            project_id='foo',
            name='ig_same_instance',
            network='global/networks/default',
            region='wl-redqueen1',
            instance_urls=[('https://www.googleapis.com/compute/v1/'
                            'projects/foo/zones/wl-redqueen1-a/instances/i1')],
        ),
    # Unmanaged; different network than ig_managed
    'ig_different_network':
        instance_group_type.InstanceGroup(
            project_id='foo',
            name='ig_different_network',
            network='global/networks/nondefault',
            region='wl-redqueen1',
            instance_urls=[('https://www.googleapis.com/compute/v1/'
                            'projects/foo/zones/wl-redqueen1-a/instances/i1')],
        ),
    # Unmanaged; different instance than ig_managed
    'ig_different_instance':
        instance_group_type.InstanceGroup(
            project_id='foo',
            name='ig5',
            network='global/networks/default',
            region='wl-redqueen1',
            instance_urls=[('https://www.googleapis.com/compute/v1/'
                            'projects/foo/zones/wl-redqueen1-a/instances/i2')],
        ),
}
INSTANCE_GROUP_MANAGERS = {
    'igm1':
        instance_group_manager_type.InstanceGroupManager(
            project_id='foo',
            name='igm1',
            instance_group=(
                'https://www.googleapis.com/compute/v1/'
                'projects/foo/regions/wl-redqueen1/instanceGroups/ig_managed'),
            instance_template=('https://www.googleapis.com/compute/v1/'
                               'projects/foo/global/instanceTemplates/it1'),
            region='wl-redqueen1',
        ),
}
INSTANCE_TEMPLATES = {
    'it1':
        instance_template_type.InstanceTemplate(
            project_id='foo',
            name='it1',
            properties={'tags': {
                'items': ['tag_it1']
            }},
        ),
}


class FakeServiceConfig(object):

    def __init__(self):
        engine = create_test_engine()
        self.model_manager = ModelManager(engine)


class IapScannerTest(ForsetiTestCase):

    def network_port(self, port_number, project='foo', network='default'):
        return iap_scanner.NetworkPort(
            network=network_type.Key.from_args(
                project_id=project, name=network),
            port=port_number)

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
            for backend_service in BACKEND_SERVICES.values():
                bs = data_access.add_resource(
                    session, 'backendservice/%s' % backend_service.name,
                    project)
                bs.data = backend_service.json
            for firewall in FIREWALL_RULES.values():
                fw = data_access.add_resource(
                    session, 'firewall/%s' % firewall.name, project)
                fw.data = firewall.as_json()
            for instance in INSTANCES.values():
                i = data_access.add_resource(
                    session, 'instance/%s' % instance.name, project)
                i.data = instance.json
            for instance_group in INSTANCE_GROUPS.values():
                ig = data_access.add_resource(
                    session, 'instancegroup/%s' % instance_group.name, project)
                ig.data = instance_group.json
            for instance_group_manager in INSTANCE_GROUP_MANAGERS.values():
                igm = data_access.add_resource(
                    session,
                    'instancegroupmanager/%s' % instance_group_manager.name,
                    project)
                igm.data = instance_group_manager.json
            for instance_template in INSTANCE_TEMPLATES.values():
                it = data_access.add_resource(
                    session, 'instancetemplate/%s' % instance_template.name,
                    project)
                it.data = instance_template.json

            session.commit()

    def setUp(self):
        self.fake_utcnow = datetime(
            year=1900,
            month=1,
            day=1,
            hour=0,
            minute=0,
            second=0,
            microsecond=0)

        self.fake_scanner_configs = {'output_path': 'gs://fake/output/path'}

        self.scanner = iap_scanner.IapScanner(
            {}, self.fake_scanner_configs, self.service_config, self.model_name,
            '', get_datafile_path(__file__, 'iap_scanner_test_data.yaml'))

        self.data = iap_scanner._RunData(
            BACKEND_SERVICES.values(),
            FIREWALL_RULES.values(),
            INSTANCES.values(),
            INSTANCE_GROUPS.values(),
            INSTANCE_GROUP_MANAGERS.values(),
            INSTANCE_TEMPLATES.values(),
        )

    def test_instance_template_map(self):
        self.assertEqual({
            INSTANCE_GROUPS['ig_managed'].key: INSTANCE_TEMPLATES['it1'],
        }, self.data.instance_templates_by_group_key)

    def test_find_instance_group(self):
        self.assertEqual(
            INSTANCE_GROUPS['ig_managed'],
            self.data.find_instance_group_by_url(
                'https://www.googleapis.com/compute/v1/'
                'projects/foo/regions/wl-redqueen1/instanceGroups/ig_managed'))

    def test_find_instance(self):
        self.assertEqual(INSTANCES['i1'],
                         self.data.find_instance_by_url(
                             'https://www.googleapis.com/compute/v1/'
                             'projects/foo/zones/wl-redqueen1-a/instances/i1'))

    def test_find_network_port(self):
        self.assertEqual(
            self.network_port(80),
            self.data.instance_group_network_port(
                BACKEND_SERVICES['bs1'], INSTANCE_GROUPS['ig_managed']))

        # ig_unmanaged overrides port mapping, so it gets a different port number
        self.assertEqual(
            self.network_port(8080),
            self.data.instance_group_network_port(
                BACKEND_SERVICES['bs1'], INSTANCE_GROUPS['ig_unmanaged']))

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
            self.data.tags_for_instance_group(INSTANCE_GROUPS['ig_managed']))
        self.assertEqual(set(),
                         self.data.tags_for_instance_group(
                             INSTANCE_GROUPS['ig_unmanaged']))

    def test_retrieve_resources(self):
        iap_resources = {}
        for (resources, _) in self.scanner._retrieve():
            iap_resources.update(
                dict((resource.backend_service.key, resource)
                     for resource in resources))

        self.maxDiff = None
        self.assertEquals(
            set([bs.key for bs in BACKEND_SERVICES.values()]),
            set(iap_resources.keys()))
        self.assertEquals(
            iap_scanner.IapResource(
                project_full_name='organization/12345/project/foo/',
                backend_service=BACKEND_SERVICES['bs1'],
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
                direct_access_sources=set(
                    ['10.0.2.0/24', 'tag_match', 'applies_all',
                     'applies_8080']),
                iap_enabled=True,
            ), iap_resources[BACKEND_SERVICES['bs1'].key])

    @mock.patch.object(
        iap_scanner.IapScanner, '_output_results_to_db', autospec=True)
    def test_run_scanner(self, mock_output_results):
        self.scanner.run()
        self.assertEquals(1, mock_output_results.call_count)

if __name__ == '__main__':
    unittest.main()
