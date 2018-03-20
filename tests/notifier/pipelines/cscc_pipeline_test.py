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

"""Tests the findings notification pipeline."""

import datetime

from google.cloud.security.notifier.pipelines import cscc_pipeline
from tests.unittest_utils import ForsetiTestCase


FAKE_VIOLATIONS = [
    {'created_at_datetime': '2018-03-13T06:28:08Z',
     'id': 10L,
     'resource_id': 'nic000',
     'resource_type': 'instance',
     'rule_index': 0L,
     'rule_name': 'all networks covered in whitelist',
     'violation_data': {u'ip': [u'104.198.99.244'],
                        u'network': u'default',
                        u'project': u'cicd000',
                        u'raw_data': u'{raw000}'},
     'violation_hash': '3bc3359d7508214bb07d28941c9ddcde687d39edb54f1b55dcbdc274532bd37fcbe5fbdbb576d67782b6b0da36ba77ae4d98703cfee7b89aff2d25884e53dc0b',
     'violation_type': 'INSTANCE_NETWORK_INTERFACE_VIOLATION'},
    {'created_at_datetime': '2018-03-13T06:28:08Z',
     'id': 11L,
     'resource_id': 'nic111',
     'resource_type': 'instance',
     'rule_index': 0L,
     'rule_name': 'all networks covered in whitelist',
     'violation_data': {u'ip': [u'104.196.168.85'],
                        u'network': u'default',
                        u'project': u'cicd111',
                        u'raw_data': u'{raw111}'},
     'violation_hash': '3c48ef8795049d7561632b5348824f1a9459192a72bcbf732edd8e7ba8ce4d9c3e07f3b13c595aba1b5cb1efad5013af1162fe6e6b9d628161950402374c137f',
     'violation_type': 'INSTANCE_NETWORK_INTERFACE_VIOLATION'}
]

EXPECTED_FINDINGS = [
    {'finding_asset_ids': 'nic000',
     'finding_callback_url': None,
     'finding_category': 'INSTANCE_NETWORK_INTERFACE_VIOLATION',
     'finding_id': '3bc3359d7508214bb07d28941c9ddcde687d39edb54f1b55dcbdc274532bd37fcbe5fbdbb576d67782b6b0da36ba77ae4d98703cfee7b89aff2d25884e53dc0b',
     'finding_properties': {'inventory_index_id': None,
                            'resource_id': 'nic000',
                            'resource_type': 'instance',
                            'rule_index': 0L,
                            'violation_data': {u'ip': [u'104.198.99.244'],
                                               u'network': u'default',
                                               u'project': u'cicd000',
                                               u'raw_data': u'{raw000}'}},
     'finding_source_id': 'FORSETI',
     'finding_summary': 'all networks covered in whitelist',
     'finding_time_event': '2018-03-13T06:28:08Z'},
    {'finding_asset_ids': 'nic111',
     'finding_callback_url': None,
     'finding_category': 'INSTANCE_NETWORK_INTERFACE_VIOLATION',
     'finding_id': '3c48ef8795049d7561632b5348824f1a9459192a72bcbf732edd8e7ba8ce4d9c3e07f3b13c595aba1b5cb1efad5013af1162fe6e6b9d628161950402374c137f',
     'finding_properties': {'inventory_index_id': None,
                            'resource_id': 'nic111',
                            'resource_type': 'instance',
                            'rule_index': 0L,
                            'violation_data': {u'ip': [u'104.196.168.85'],
                                               u'network': u'default',
                                               u'project': u'cicd111',
                                               u'raw_data': u'{raw111}'}},
     'finding_source_id': 'FORSETI',
     'finding_summary': 'all networks covered in whitelist',
     'finding_time_event': '2018-03-13T06:28:08Z'}
]


class CsccPipelineTest(ForsetiTestCase):

    def setUp(self):
        """Setup method."""
        ForsetiTestCase.setUp(self)
        self.maxDiff=None

    def tearDown(self):
        """Tear down method."""
        ForsetiTestCase.tearDown(self)

    def test_can_convert_violations_to_findings(self):

        findings = (
            cscc_pipeline.CsccPipeline()._transform_to_findings(
                FAKE_VIOLATIONS))

        self.assertEquals(EXPECTED_FINDINGS, findings)
