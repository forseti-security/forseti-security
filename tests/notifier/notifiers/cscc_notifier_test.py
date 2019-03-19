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

"""Tests the CSCC notification notifier."""

import ast
import datetime
import json
import mock

from google.cloud.forseti.notifier import notifier
from google.cloud.forseti.notifier.notifiers import cscc_notifier
from google.cloud.forseti.services.scanner import dao as scanner_dao
from tests.services.scanner import scanner_base_db


class CsccNotifierTest(scanner_base_db.ScannerBaseDbTestCase):

    def setUp(self):
        """Setup method."""
        super(CsccNotifierTest, self).setUp()
        self.maxDiff = None

    def tearDown(self):
        """Tear down method."""
        super(CsccNotifierTest, self).tearDown()

    @mock.patch('google.cloud.forseti.common.util.date_time.'
                'get_utc_now_datetime')
    def _populate_and_retrieve_violations(self, mock_get_utc_now):
        fake_datetime = datetime.datetime(2010, 8, 28, 10, 20, 30, 0)
        mock_get_utc_now.return_value = fake_datetime

        scanner_index_id = self.populate_db(inv_index_id=self.inv_index_id2)

        violations = self.violation_access.list(
            scanner_index_id=scanner_index_id)

        violations_as_dict = []
        for violation in violations:
            violations_as_dict.append(
                scanner_dao.convert_sqlalchemy_object_to_dict(violation))

        violations_as_dict = notifier.convert_to_timestamp(violations_as_dict)

        return violations_as_dict

    def test_can_transform_to_beta_findings_in_api_mode(self):

        expected_beta_findings = [
            ['539cfbdb1113a74ec18edf583eada77a',
             {'category': 'FIREWALL_BLACKLIST_VIOLATION_111',
              'resource_name': 'full_name_111',
              'name': 'organizations/11111/sources/22222/findings/539cfbdb1113a74ec18edf583eada77a',
              'parent': 'organizations/11111/sources/22222',
              'event_time': '2010-08-28T10:20:30Z',
              'state': 'ACTIVE',
              'source_properties': {
                  'source': 'FORSETI',
                  'rule_name': 'disallow_all_ports_111',
                  'inventory_index_id': 'iii',
                  'resource_data': '"inventory_data_111"',
                  'db_source': 'table:violations/id:1',
                  'rule_index': 111,
                  'violation_data': '"{\\"policy_names\\": [\\"fw-tag-match_111\\"], \\"recommended_actions\\": {\\"DELETE_FIREWALL_RULES\\": [\\"fw-tag-match_111\\"]}}"',
                  'resource_id': 'fake_firewall_111',
                  'scanner_index_id': 1282990830000000,
                  'resource_type': 'firewall_rule'}}],
            ['3eff279ccb96799d9eb18e6b76055b22',
             {'category': 'FIREWALL_BLACKLIST_VIOLATION_222',
              'resource_name': 'full_name_222',
              'name': 'organizations/11111/sources/22222/findings/3eff279ccb96799d9eb18e6b76055b22',
              'parent': 'organizations/11111/sources/22222',
              'event_time': '2010-08-28T10:20:30Z',
              'state': 'ACTIVE',
              'source_properties': {
                  'source': 'FORSETI',
                  'rule_name': 'disallow_all_ports_222',
                  'inventory_index_id': 'iii',
                  'resource_data': '"inventory_data_222"',
                  'db_source': 'table:violations/id:2',
                  'rule_index': 222,
                  'violation_data': '"{\\"policy_names\\": [\\"fw-tag-match_222\\"], \\"recommended_actions\\": {\\"DELETE_FIREWALL_RULES\\": [\\"fw-tag-match_222\\"]}}"',
                  'resource_id': 'fake_firewall_222',
                  'scanner_index_id': 1282990830000000,
                  'resource_type': 'firewall_rule'}}]]

        violations_as_dict = self._populate_and_retrieve_violations()

        finding_results = (
            cscc_notifier.CsccNotifier('iii')._transform_for_api(
                violations_as_dict,
                source_id='organizations/11111/sources/22222'))

        self.assertEquals(expected_beta_findings,
                          ast.literal_eval(json.dumps(finding_results)))

    @mock.patch('google.cloud.forseti.common.util.date_time.'
                'get_utc_now_datetime')
    def test_can_transform_to_findings_in_bucket_mode(self, mock_get_utc_now):

        expected_findings = [
            {'finding_id': '539cfbdb1113a74ec18edf583eada77ab1a60542c6edcb4120b50f34629b6b69041c13f0447ab7b2526d4c944c88670b6f151fa88444c30771f47a3b813552ff',
             'finding_summary': 'disallow_all_ports_111',
             'finding_source_id': 'FORSETI', 
             'finding_category': 'FIREWALL_BLACKLIST_VIOLATION_111', 
             'finding_asset_ids': 'full_name_111',
             'finding_time_event': '2010-08-28T10:20:30Z',
             'finding_callback_url': 'gs://foo_bucket',
             'finding_properties':
                 {'db_source': 'table:violations/id:1',
                  'inventory_index_id': 'iii',
                  'resource_id': 'fake_firewall_111',
                  'resource_data': 'inventory_data_111',
                  'rule_index': 111,
                  'scanner_index_id': 1282990830000000,
                  'violation_data': '{"policy_names": ["fw-tag-match_111"], "recommended_actions": {"DELETE_FIREWALL_RULES": ["fw-tag-match_111"]}}', 'resource_type': u'firewall_rule'},
             },
           {'finding_id': '3eff279ccb96799d9eb18e6b76055b2242d1f2e6f14c1fb3bb48f7c8c03b4ce4db577d67c0b91c5914902d906bf1703d5bbba0ceaf29809ac90fef3bf6aa5417',
            'finding_summary': 'disallow_all_ports_222',
            'finding_source_id': 'FORSETI',
            'finding_category': 'FIREWALL_BLACKLIST_VIOLATION_222',
            'finding_asset_ids': 'full_name_222',
            'finding_time_event': '2010-08-28T10:20:30Z',
            'finding_callback_url': 'gs://foo_bucket',
            'finding_properties':
                {'db_source': 'table:violations/id:2',
                 'inventory_index_id': 'iii',
                 'resource_id': 'fake_firewall_222',
                 'resource_data': 'inventory_data_222',
                 'rule_index': 222,
                 'scanner_index_id': 1282990830000000,
                 'violation_data': '{"policy_names": ["fw-tag-match_222"], "recommended_actions": {"DELETE_FIREWALL_RULES": ["fw-tag-match_222"]}}', 'resource_type': u'firewall_rule'},
            }
        ]

        violations_as_dict = self._populate_and_retrieve_violations()

        finding_results = (
            cscc_notifier.CsccNotifier('iii')._transform_for_gcs(
                violations_as_dict, 'gs://foo_bucket')
        )

        self.assertEquals(expected_findings, finding_results)
    
    def test_beta_api_is_invoked_correctly(self):

        notifier = cscc_notifier.CsccNotifier(None)

        notifier._send_findings_to_cscc = mock.MagicMock()
        notifier.LOGGER = mock.MagicMock()

        self.assertEquals(0, notifier._send_findings_to_cscc.call_count)
        notifier.run(None, source_id='111')
        
        calls = notifier._send_findings_to_cscc.call_args_list
        call = calls[0]
        _, kwargs = call
        
        self.assertEquals('111', kwargs['source_id'])

    def test_outdated_findings_are_found(self):

        NEW_FINDINGS = [['abc',
                            {'category': 'BUCKET_VIOLATION',
                             'resource_name': 'organization/123/project/inventoryscanner/bucket/isthispublic/',
                             'name': 'organizations/123/sources/560/findings/abc',
                             'parent': 'organizations/123/sources/560',
                             'event_time': '2019-03-12T16:06:19Z',
                             'state': 'ACTIVE',
                             'source_properties': {'source': 'FORSETI',
                                                   'rule_name': 'Bucket acls rule to search for public buckets',
                                                   'inventory_index_id': 789,
                                                   'resource_data': '{"bucket": "isthispublic", "entity": "allUsers", "id": "isthispublic/allUsers", "role": "READER"}',
                                                   'db_source': 'table:violations/id:94953',
                                                   'rule_index': 0L,
                                                   'violation_data': '{"bucket": "isthispublic", "domain": "", "email": "", "entity": "allUsers", "full_name": "organization/123/project/inventoryscanner/bucket/isthispublic/", "project_id": "inventoryscanner-henry", "role": "READER"}',
                                                   'resource_id': 'isthispublic',
                                                   'scanner_index_id': 1551913369403591L,
                                                   'resource_type': 'bucket'}}]]

        FINDINGS_IN_CSCC = [['ffe',
                            {'category': 'BUCKET_VIOLATION',
                             'resource_name': 'organization/123/project/inventoryscanner/bucket/isthispublic/',
                             'name': 'organizations/123/sources/560/findings/ffe',
                             'parent': 'organizations/123/sources/560',
                             'event_time': '2019-03-12T16:06:19Z',
                             'state': 'ACTIVE',
                             'source_properties': {'source': 'FORSETI',
                                                   'rule_name': 'Bucket acls rule to search for public buckets',
                                                   'inventory_index_id': 789,
                                                   'resource_data': '{"bucket": "isthispublic", "entity": "allUsers", "id": "isthispublic/allUsers", "role": "READER"}',
                                                   'db_source': 'table:violations/id:94953',
                                                   'rule_index': 0L,
                                                   'violation_data': '{"bucket": "isthispublic", "domain": "", "email": "", "entity": "allUsers", "full_name": "organization/123/project/inventoryscanner/bucket/isthispublic/", "project_id": "inventoryscanner", "role": "READER"}',
                                                   'resource_id': 'isthispublic',
                                                   'scanner_index_id': 1551913369403591L,
                                                   'resource_type': 'bucket'}}]]

        EXPECTED_INACTIVE_FINDINGS = [['ffe',
                            {'category': 'BUCKET_VIOLATION',
                             'resource_name': 'organization/123/project/inventoryscanner-henry/bucket/isthispublic/',
                             'name': 'organizations/123/sources/560/findings/ffe',
                             'parent': 'organizations/123/sources/560',
                             'event_time': '2019-03-12T16:06:19Z',
                             'state': 'INACTIVE',
                             'source_properties': {'source': 'FORSETI',
                                                   'rule_name': 'Bucket acls rule to search for public buckets',
                                                   'inventory_index_id': 789,
                                                   'resource_data': '{"bucket": "isthispublic", "entity": "allUsers", "id": "isthispublic/allUsers", "role": "READER"}',
                                                   'db_source': 'table:violations/id:94953',
                                                   'rule_index': 0L,
                                                   'violation_data': '{"bucket": "isthispublic", "domain": "", "email": "", "entity": "allUsers", "full_name": "organization/123/project/inventoryscanner/bucket/isthispublic/", "project_id": "inventoryscanner", "role": "READER"}',
                                                   'resource_id': 'isthispublic',
                                                   'scanner_index_id': 1551913369403591L,
                                                   'resource_type': 'bucket'}}]]

        notifier = cscc_notifier.CsccNotifier('123')

        inactive_findings = notifier.find_inactive_findings(NEW_FINDINGS,
                                                            FINDINGS_IN_CSCC)
        self.assertEquals(EXPECTED_INACTIVE_FINDINGS[0][1]['state'],
                          inactive_findings[0][1]['state'])

    def test_outdated_findings_are_not_found(self):

        NEW_FINDINGS = [['abc',
                            {'category': 'BUCKET_VIOLATION',
                             'resource_name': 'organization/123/project/inventoryscanner/bucket/isthispublic/',
                             'name': 'organizations/123/sources/560/findings/abc',
                             'parent': 'organizations/123/sources/560',
                             'event_time': '2019-03-12T16:06:19Z',
                             'state': 'ACTIVE',
                             'source_properties': {'source': 'FORSETI',
                                                   'rule_name': 'Bucket acls rule to search for public buckets',
                                                   'inventory_index_id': 789,
                                                   'resource_data': '{"bucket": "isthispublic", "entity": "allUsers", "id": "isthispublic/allUsers", "role": "READER"}',
                                                   'db_source': 'table:violations/id:94953',
                                                   'rule_index': 0L,
                                                   'violation_data': '{"bucket": "isthispublic", "domain": "", "email": "", "entity": "allUsers", "full_name": "organization/123/project/inventoryscanner/bucket/isthispublic/", "project_id": "inventoryscanner-henry", "role": "READER"}',
                                                   'resource_id': 'isthispublic',
                                                   'scanner_index_id': 1551913369403591L,
                                                   'resource_type': 'bucket'}}]]

        FINDINGS_IN_CSCC = [['abc',
                            {'category': 'BUCKET_VIOLATION',
                             'resource_name': 'organization/123/project/inventoryscanner/bucket/isthispublic/',
                             'name': 'organizations/123/sources/560/findings/abc',
                             'parent': 'organizations/123/sources/560',
                             'event_time': '2019-03-12T16:06:19Z',
                             'state': 'ACTIVE',
                             'source_properties': {'source': 'FORSETI',
                                                   'rule_name': 'Bucket acls rule to search for public buckets',
                                                   'inventory_index_id': 789,
                                                   'resource_data': '{"bucket": "isthispublic", "entity": "allUsers", "id": "isthispublic/allUsers", "role": "READER"}',
                                                   'db_source': 'table:violations/id:94953',
                                                   'rule_index': 0L,
                                                   'violation_data': '{"bucket": "isthispublic", "domain": "", "email": "", "entity": "allUsers", "full_name": "organization/123/project/inventoryscanner/bucket/isthispublic/", "project_id": "inventoryscanner-henry", "role": "READER"}',
                                                   'resource_id': 'isthispublic',
                                                   'scanner_index_id': 1551913369403591L,
                                                   'resource_type': 'bucket'}}]]

        notifier = cscc_notifier.CsccNotifier('123')

        inactive_findings = notifier.find_inactive_findings(NEW_FINDINGS,
                                                            FINDINGS_IN_CSCC)

        assert(len(inactive_findings)) == 0
