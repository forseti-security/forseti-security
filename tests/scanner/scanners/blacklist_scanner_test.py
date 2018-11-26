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

"""Blacklist Scanner Test"""

import mock
from mock import patch, Mock
from tests.unittest_utils import ForsetiTestCase
from google.cloud.forseti.common.gcp_type import instance
from google.cloud.forseti.scanner.scanners import blacklist_scanner
from google.cloud.forseti.scanner.audit import blacklist_rules_engine as bre

from tests.scanner.test_data import fake_blacklist_scanner_data as fbsd
from tests.unittest_utils import get_datafile_path

def create_list_of_instence_network_interface_obj_from_data():
    fake_instances_list = []
    for data in fbsd.INSTANCE_DATA:
        fake_instances_list.append(
            instance.Instance(
                'fake-instance', **data).create_network_interfaces())
    return fake_instances_list

class BlacklistScannerTest(ForsetiTestCase):

    @patch('google.cloud.forseti.scanner.audit.' + \
           'blacklist_rules_engine.urllib2.urlopen')
    def test_get_blacklist_url(self, mock_urlopen):
        a = Mock()
        a.read.side_effect = [fbsd.FAKE_BLACKLIST_SOURCE_1]
        mock_urlopen.return_value = a

        output = bre.BlacklistRuleBook.get_and_parse_blacklist('')
        self.assertEqual(2, len(output))
        self.assertEqual(sorted(fbsd.EXPECTED_BLACKLIST_1), sorted(output))
        return output

    @patch('google.cloud.forseti.scanner.audit.' + \
           'blacklist_rules_engine.urllib2.urlopen')
    def test_build_rule_book_from_local_yaml_file_works(self, mock_urlopen):
        """Test that a RuleBook is built correctly with a yaml file."""
        a = Mock()
        a.read.side_effect = [fbsd.FAKE_BLACKLIST_SOURCE_1,
                              fbsd.FAKE_BLACKLIST_SOURCE_2]
        mock_urlopen.return_value = a

        rules_local_path = get_datafile_path(__file__, 'blacklist_test_rule.yaml')
        rules_engine = bre.BlacklistRulesEngine(rules_file_path=rules_local_path)
        rules_engine.build_rule_book({})
        self.assertEqual(2, len(rules_engine.rule_book.resource_rules_map))
        self.assertEqual('http://threatintel.localdomain/verybadips.txt',
                          rules_engine.rule_book.rule_defs['rules'][0]['url'])

    @patch('google.cloud.forseti.scanner.audit.' + \
           'blacklist_rules_engine.urllib2.urlopen')
    def test_blacklist_scanner_all_match(self, mock_urlopen):
        a = Mock()
        a.read.side_effect = [fbsd.FAKE_BLACKLIST_SOURCE_1,
                              fbsd.FAKE_BLACKLIST_SOURCE_2]
        mock_urlopen.return_value = a

        rules_local_path = get_datafile_path(__file__, 'blacklist_test_rule.yaml')
        scanner = blacklist_scanner.BlacklistScanner(
            {}, {}, mock.MagicMock(), '', '', rules_local_path)
        netifs = create_list_of_instence_network_interface_obj_from_data()

        for netif, expected_violation in zip(netifs, fbsd.EXPECTED_VIOLATIONS):
            violation = scanner._find_violations([netif])
            self.assertEqual(expected_violation, violation)

if __name__ == '__main__':
    unittest.main()
