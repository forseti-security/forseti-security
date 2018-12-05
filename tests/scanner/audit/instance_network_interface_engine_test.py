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

"""Tests the EnforcedNetworkRulesEngine."""

import unittest
import mock
import yaml

from tests import unittest_utils
from tests.scanner.test_data import fake_instance_scanner_data

from google.cloud.forseti.common.gcp_type import instance
from google.cloud.forseti.common.util import file_loader
from google.cloud.forseti.scanner.audit import instance_network_interface_rules_engine as ini


def create_list_of_instence_network_interface_obj_from_data():
    fake_instance_scanner_list = []
    for data in fake_instance_scanner_data.INSTANCE_DATA:
        fake_instance_scanner_list.append(
            instance.Instance(
                'fake-instance', **data).create_network_interfaces())
    return fake_instance_scanner_list


# TODO: Define more tests
class InstanceNetworkInterfaceTest(unittest_utils.ForsetiTestCase):
    """Tests for the InstanceNetworkInterface."""

    def setUp(self):
        """Set up."""
        self.rule_index = 0
        self.ini = ini
        self.ini.LOGGER = mock.MagicMock()

    def test_build_rule_book_from_local_yaml_file_works(self):
        """Test that a RuleBook is built correctly
        with a yaml file."""
        rules_local_path = unittest_utils.get_datafile_path(
            __file__,
            'instance_network_interface_test_rules_1.yaml')
        rules_engine = ini.InstanceNetworkInterfaceRulesEngine(
            rules_file_path=rules_local_path)
        rules_engine.build_rule_book()
        self.assertEqual(1, len(rules_engine.rule_book.resource_rules_map))

    @mock.patch.object(file_loader,
                       '_read_file_from_gcs', autospec=True)
    def test_build_rule_book_from_gcs_works(self, mock_load_rules_from_gcs):
        """Test that a RuleBook is built correctly with a mocked gcs file.

        Setup:
            * Create a mocked GCS object from a test yaml file.
            * Get the yaml file content.

        Expected results:
            There are 2 resources that have rules, in the rule book.
        """
        bucket_name = 'bucket-name'
        rules_path = 'input/instance_network_interface_test_rules_1.yaml'
        full_rules_path = 'gs://{}/{}'.format(bucket_name, rules_path)
        rules_engine = ini.InstanceNetworkInterfaceRulesEngine(
            rules_file_path=full_rules_path)

        # Read in the rules file
        file_content = None
        with open(
            unittest_utils.get_datafile_path(
                __file__, 'instance_network_interface_test_rules_1.yaml'),
            'r') as rules_local_file:
            try:
                file_content = yaml.safe_load(rules_local_file)
            except yaml.YAMLError:
                raise

        mock_load_rules_from_gcs.return_value = file_content

        rules_engine.build_rule_book()
        self.assertEqual(1, len(rules_engine.rule_book.resource_rules_map))

    def test_networks_in_whitelist_and_allowed_projects(self):
        """Test to make sure violations are created"""
        rules_local_path = unittest_utils.get_datafile_path(
            __file__,
            'instance_network_interface_test_rules_2.yaml')
        rules_engine = ini.InstanceNetworkInterfaceRulesEngine(rules_local_path)
        rules_engine.build_rule_book()
        fake_ini_data = (
            create_list_of_instence_network_interface_obj_from_data())
        actual_violations_list = []
        for instance_network_interface in fake_ini_data:
            violation = rules_engine.find_violations(
                instance_network_interface)
            actual_violations_list.extend(violation)
        self.assertEqual([], actual_violations_list)

    def test_network_in_allowed_project_but_not_whitelist_with_extern_ip(self):
        """Test to make sure violations are created where the project
        is allowed but not the network is not and there is an external ip"""
        rules_local_path = unittest_utils.get_datafile_path(
            __file__,
            'instance_network_interface_test_rules_3.yaml')
        rules_engine = ini.InstanceNetworkInterfaceRulesEngine(
            rules_local_path)
        rules_engine.build_rule_book()
        fake_ini_data = (
            create_list_of_instence_network_interface_obj_from_data())
        actual_violations_list = []
        for instance_network_interface in fake_ini_data:
            violation = rules_engine.find_violations(
                instance_network_interface)
            actual_violations_list.extend(violation)
        self.assertEqual(1, len(actual_violations_list))
        self.assertEqual('project-1', actual_violations_list[0].project)
        self.assertEqual('network-1', actual_violations_list[0].network)

    def test_network_in_allowed_project_with_no_external_ip(self):
        """Test to make sure violations are not created where the project
        is allowed but not the network is not and there is not an
        external ip"""
        rules_local_path = unittest_utils.get_datafile_path(
            __file__,
            'instance_network_interface_test_rules_4.yaml')
        rules_engine = ini.InstanceNetworkInterfaceRulesEngine(rules_local_path)
        rules_engine.build_rule_book()
        fake_ini_data = (
            create_list_of_instence_network_interface_obj_from_data())
        actual_violations_list = []
        for instance_network_interface in fake_ini_data:
            violation = rules_engine.find_violations(
                instance_network_interface)
            actual_violations_list.extend(violation)
        self.assertEqual([], actual_violations_list)

    def test_network_not_in_allowed_project(self):
        """Test to make sure violations are where the project
        is not allowed"""
        rules_local_path = unittest_utils.get_datafile_path(
            __file__,
            'instance_network_interface_test_rules_5.yaml')
        rules_engine = ini.InstanceNetworkInterfaceRulesEngine(rules_local_path)
        rules_engine.build_rule_book()
        fake_ini_data = (
            create_list_of_instence_network_interface_obj_from_data())
        actual_violations_list = []
        for instance_network_interface in fake_ini_data:
            violation = rules_engine.find_violations(
                instance_network_interface)
            actual_violations_list.extend(violation)
        self.assertEqual(1, len(actual_violations_list))
        self.assertEqual('project-3', actual_violations_list[0].project)
        self.assertEqual('network-3', actual_violations_list[0].network)


if __name__ == "__main__":
    unittest.main()
