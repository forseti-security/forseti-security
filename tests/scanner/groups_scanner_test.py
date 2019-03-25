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

"""Scanner runner script test."""

import json
import mock

import anytree
import unittest
import yaml

from tests.unittest_utils import ForsetiTestCase
from google.cloud.forseti.scanner.scanners import groups_scanner
from tests.scanner.test_data import fake_groups_scanner_data as fake_data


class GroupsScannerTest(ForsetiTestCase):

    def setUp(self):
        pass

    def _render_ascii(self, starting_node, attr):
        """Render an ascii representation of the tree structure.

        Args:
            starting_node: The starting node to render the ascii.

        Returns:
            attr: String of the attribute to render.
        """
        rows = []
        for pre, fill, node in anytree.RenderTree(starting_node,
                                                  style=anytree.AsciiStyle()):
            value = getattr(node, attr, "")
            if isinstance(value, (list, tuple)):
                lines = value
            else:
                lines = str(value).split("\n")
            rows.append(u"%s%s" % (pre,
                                   json.dumps(lines[0], sort_keys=True)))
            for line in lines[1:]:
                rows.append(u"%s%s" % (fill,
                                       json.dumps(line, sort_keys=True)))

        return '\n'.join(rows)

    def _create_mock_service_config(self):
        mock_data_access = mock.MagicMock()
        mock_data_access.iter_groups.return_value = fake_data.ALL_GROUPS
        mock_data_access.return_value = fake_data.ALL_GROUPS

        mock_data_access.expand_members.side_effect = [
            fake_data.AAAAA_GROUP_MEMBERS,
            fake_data.BBBBB_GROUP_MEMBERS,
            fake_data.CCCCC_GROUP_MEMBERS,
            fake_data.DDDDD_GROUP_MEMBERS]

        mock_service_config = mock.MagicMock()
        mock_service_config.model_manager.get.return_value = (
            mock.MagicMock(), mock_data_access)
        
        return mock_service_config

    def test_groups_scanner(self):

        # test tree of groups can be built successfully
        mock_service_config = self._create_mock_service_config()
        scanner = groups_scanner.GroupsScanner(
            {}, {}, mock_service_config, '', '', '')
        root = scanner._build_group_tree()
        self.assertEquals(fake_data.EXPECTED_MEMBERS_IN_TREE,
                          self._render_ascii(root, 'member_email'))

        # test rules will be associated to the correct nodes
        with open('tests/scanner/test_data/fake_group_rules.yaml', 'r') as f:
            rules = yaml.load(f)
        root_with_rules = scanner._apply_all_rules(root, rules)
        self.assertEquals(fake_data.EXPECTED_MEMBERS_IN_TREE,
                          self._render_ascii(root_with_rules, 'member_email'))
        self.assertEquals(fake_data.EXPECTED_RULES_IN_TREE,
                          self._render_ascii(root_with_rules, 'rules'))

        # test violations are found correctly
        all_violations = scanner._find_violations(root_with_rules)
        self.assertEquals(3, len(all_violations))
        for violation in all_violations:
            self.assertEquals('christy@yahoo.com', violation.member_email)


if __name__ == '__main__':
    unittest.main()
