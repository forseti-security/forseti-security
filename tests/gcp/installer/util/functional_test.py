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

"""Tests for setup/gcp/installer/util/files.py."""

import unittest
import os

import setup.gcp.installer.util.files as files
import setup.gcp.installer.util.merge_engine as merge_engine

from tests.unittest_utils import ForsetiTestCase

TEST_RESOURCE_DIR_PATH = os.path.join(
    os.path.dirname(__file__), 'test_data')


class FunctionalTest(ForsetiTestCase):

    def deep_sort(self, obj):
        """Recursively nested lists or dictionaries.

        Args:
            obj (object): Objects to sort.
        """

        if isinstance(obj, dict):
            _sorted = {}
            for key in sorted(obj):
                _sorted[key] = self.deep_sort(obj[key])

        elif isinstance(obj, list):
            new_list = []
            for val in obj:
                new_list.append(self.deep_sort(val))
            _sorted = sorted(new_list)

        else:
            _sorted = obj

        return _sorted

    def test_merge_conf_yaml_files(self):
        """Merge 2 conf yaml files."""
        self.maxDiff = None
        # Load yaml files
        merge_to_path = os.path.join(TEST_RESOURCE_DIR_PATH,
                                 'merge_to_forseti_conf_server.yaml')
        merge_from_path = os.path.join(TEST_RESOURCE_DIR_PATH,
                                   'merge_from_forseti_conf.yaml')
        merged_path = os.path.join(TEST_RESOURCE_DIR_PATH,
                                   'merged_forseti_conf_server.yaml')

        merge_to = files.read_yaml_file_from_local(merge_to_path)
        merge_from = files.read_yaml_file_from_local(merge_from_path)
        expected_merged_obj = files.read_yaml_file_from_local(merged_path)

        # Merge target into base, ignore gcs_path and output_path
        fields_to_ignore = [
            'db_host', 'db_user', 'db_name',
            'inventory', 'output_path', 'gcs_path',
            'groups_service_account_key_file',
            'domain_super_admin_email',
            'max_admin_api_calls_per_100_seconds',
            'max_appengine_api_calls_per_second',
            'max_bigquery_api_calls_per_100_seconds',
            'max_cloudbilling_api_calls_per_60_seconds',
            'max_compute_api_calls_per_second',
            'max_container_api_calls_per_100_seconds',
            'max_crm_api_calls_per_100_seconds',
            'max_iam_api_calls_per_second',
            'max_servicemanagement_api_calls_per_100_seconds',
            'max_sqladmin_api_calls_per_100_seconds',
            'max_results_admin_api']
        field_identifiers = {'scanners': 'name',
                             'resources': 'resource',
                             'pipelines': 'name'}

        merge_engine.merge_object(merge_from, merge_to,
                                  fields_to_ignore, field_identifiers)

        merge_to = self.deep_sort(merge_to)
        expected_merged_obj = self.deep_sort(expected_merged_obj)

        self.assertEqual(expected_merged_obj, merge_to)

    def test_merge_bucket_rule_yaml_files(self):
        """Merge 2 conf yaml files."""
        self.maxDiff = None
        # Load yaml files
        base_path = os.path.join(TEST_RESOURCE_DIR_PATH,
                                 'merge_to_bucket_rules.yaml')
        target_path = os.path.join(TEST_RESOURCE_DIR_PATH,
                                   'merge_from_bucket_rules.yaml')
        merged_path = os.path.join(TEST_RESOURCE_DIR_PATH,
                                   'merged_bucket_rules.yaml')

        merge_to = files.read_yaml_file_from_local(base_path)
        merge_from = files.read_yaml_file_from_local(target_path)
        expected_merged_obj = files.read_yaml_file_from_local(merged_path)

        # Merge target into base, ignore gcs_path and output_path
        fields_to_ignore = []
        field_identifiers = {'rules': 'name'}

        merge_engine.merge_object(merge_from, merge_to,
                                  fields_to_ignore, field_identifiers)

        merge_to = self.deep_sort(merge_to)
        expected_merged_obj = self.deep_sort(expected_merged_obj)

        self.assertEqual(expected_merged_obj, merge_to)

    def test_merge_group_rule_yaml_files(self):
        """Merge 2 conf yaml files."""
        self.maxDiff = None
        # Load yaml files
        base_path = os.path.join(TEST_RESOURCE_DIR_PATH,
                                 'merge_to_group_rules.yaml')
        target_path = os.path.join(TEST_RESOURCE_DIR_PATH,
                                   'merge_from_group_rules.yaml')
        merged_path = os.path.join(TEST_RESOURCE_DIR_PATH,
                                   'merged_group_rules.yaml')

        merge_to = files.read_yaml_file_from_local(base_path)
        merge_from = files.read_yaml_file_from_local(target_path)
        expected_merged_obj = files.read_yaml_file_from_local(merged_path)

        # Merge target into base, ignore gcs_path and output_path
        fields_to_ignore = []
        field_identifiers = {'default_identifier': 'name'}

        merge_engine.merge_object(merge_from, merge_to,
                                  fields_to_ignore, field_identifiers)

        merge_to = self.deep_sort(merge_to)
        expected_merged_obj = self.deep_sort(expected_merged_obj)

        self.assertEqual(expected_merged_obj, merge_to)

    def test_merge_iam_rule_yaml_files(self):
        """Merge 2 conf yaml files."""
        self.maxDiff = None
        # Load yaml files
        base_path = os.path.join(TEST_RESOURCE_DIR_PATH,
                                 'merge_to_iam_rules.yaml')
        target_path = os.path.join(TEST_RESOURCE_DIR_PATH,
                                   'merge_from_iam_rules.yaml')
        merged_path = os.path.join(TEST_RESOURCE_DIR_PATH,
                                   'merged_iam_rules.yaml')

        merge_to = files.read_yaml_file_from_local(base_path)
        merge_from = files.read_yaml_file_from_local(target_path)
        expected_merged_obj = files.read_yaml_file_from_local(merged_path)

        # Merge target into base, ignore gcs_path and output_path
        fields_to_ignore = []
        field_identifiers = {'rules': 'name', 'bindings': 'role', 'default_identifier': 'name'}

        merge_engine.merge_object(merge_from, merge_to,
                                  fields_to_ignore, field_identifiers)

        merge_to = self.deep_sort(merge_to)
        expected_merged_obj = self.deep_sort(expected_merged_obj)

        self.assertEqual(expected_merged_obj, merge_to)


    def test_merge_firewall_rule_yaml_files(self):
        """Merge 2 conf yaml files."""
        self.maxDiff = None
        # Load yaml files
        base_path = os.path.join(TEST_RESOURCE_DIR_PATH,
                                 'merge_to_firewall_rules.yaml')
        target_path = os.path.join(TEST_RESOURCE_DIR_PATH,
                                   'merge_from_firewall_rules.yaml')
        merged_path = os.path.join(TEST_RESOURCE_DIR_PATH,
                                   'merged_firewall_rules.yaml')

        merge_to = files.read_yaml_file_from_local(base_path)
        merge_from = files.read_yaml_file_from_local(target_path)
        expected_merged_obj = files.read_yaml_file_from_local(merged_path)

        # Merge target into base, ignore gcs_path and output_path
        fields_to_ignore = []
        field_identifiers = {'rules': ['name', 'rule_id'],
                             'rule_groups': 'group_id', 'resources': 'type'}

        merge_engine.merge_object(merge_from, merge_to,
                                  fields_to_ignore, field_identifiers)

        merge_to = self.deep_sort(merge_to)
        expected_merged_obj = self.deep_sort(expected_merged_obj)

        self.assertEqual(expected_merged_obj, merge_to)

if __name__ == '__main__':
    unittest.main()
