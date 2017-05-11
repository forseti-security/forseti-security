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

"""Scanner runner script test."""

import pickle
import mock

import anytree
import yaml

from google.apputils import basetest
from google.cloud.security.scanner.scanners import groups_scanner
from tests.scanner.test_data import fake_groups_scanner_data as fake_data


class GroupsScannerTest(basetest.TestCase):

    def _pickle_dump(self, obj, filename):
        """Dump object to pickle file.

        Args:
            obj: Any object to be pickled.
            filename: String of the pickle filename.

        Returns:
             None
        """
        pickle.dump(obj, open('tests/scanner/test_data/' + filename, 'wb'))

    def _pickle_load(self, filename):
        """Loads a pickle file.

        Args:
            filename: String of the pickle filename to load.

        Returns:
            obj: The object that was pickled.
        """
        return pickle.load(open('tests/scanner/test_data/' + filename, 'rb'))

    def _render_ascii(self, starting_node, attr):
        """Render an ascii representation of the tree structure.

        Args:
            starting_node: The starting node to render the ascii.

        Returns:
            attr: String of the attribute to render.
        """
        return anytree.RenderTree(
            starting_node,
            style=anytree.AsciiStyle()).by_attr(attr)

    def setUp(self):
        pass

    @mock.patch('google.cloud.security.scanner.scanners.groups_scanner.group_dao.GroupDao', spec=True)
    def test_build_group_tree(self, mock_dao):

        mock_dao.get_all_groups.return_value = fake_data.ALL_GROUPS
        mock_dao.get_group_members.side_effect = fake_data.ALL_GROUP_MEMBERS

        scanner = groups_scanner.GroupsScanner('')
        scanner.dao = mock_dao
        root = scanner._build_group_tree('')

        self.assertEquals(fake_data.EXPECTED_MEMBERS_IN_TREE,
                          self._render_ascii(root, 'member_email'))        

    @mock.patch('google.cloud.security.scanner.scanners.groups_scanner.group_dao.GroupDao', spec=True)
    def test_apply_rule(self, mock_dao):

        root = self._pickle_load('expected_root_without_rules.pickle')
        with open('tests/scanner/test_data/fake_group_rules.yaml', 'r') as f:
            rules = yaml.load(f)

        scanner = groups_scanner.GroupsScanner('')
        root_with_rules = scanner._apply_all_rules(root, rules)

        self.assertEquals(fake_data.EXPECTED_MEMBERS_IN_TREE,
                          self._render_ascii(root_with_rules, 'member_email'))        
        self.assertEquals(fake_data.EXPECTED_RULES_IN_TREE,
                          self._render_ascii(root_with_rules, 'rules'))

    @mock.patch('google.cloud.security.scanner.scanners.groups_scanner.group_dao.GroupDao', spec=True)
    def test_find_violations(self, mock_dao):
        root = self._pickle_load('expected_root_with_rules.pickle')
        scanner = groups_scanner.GroupsScanner('')
        all_violations = scanner.find_violations(root)
        
        self.assertEquals(3, len(all_violations))
        
        for violation in all_violations:
            self.assertEquals('christy@gmail.com', violation.member_email)


if __name__ == '__main__':
    basetest.main()
