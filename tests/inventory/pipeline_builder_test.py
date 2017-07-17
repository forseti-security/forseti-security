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

"""Tests the pipeline builder."""

import mock
import unittest

from google.cloud.security.tests.unittest_utils import ForsetiTestCase
from google.cloud.security.common.util import file_loader
from google.cloud.security.inventory import api_map
from google.cloud.security.inventory import pipeline_builder
from tests.inventory.test_data import fake_runnable_pipelines


BASE_PATH = 'tests/inventory/test_data/'
FAKE_TIMESTAMP = '20001225T121212Z'

class PipelineBuilderTest(ForsetiTestCase):
    """Tests for the load pipeline builder test.

    The test data has this structure.

    organizations
    |-- folders
    |-- groups
    |   +-- group_members
    |-- org_iam_policies
    +-- projects
        |-- bigquery_datasets
        |-- firewall_rules
        |-- forwarding_rules
        |-- buckets
        |   +-- buckets_acls
        |-- cloudsql
        +-- projects_iam_policies

    """

    def _verify_resource_names_in_pipelines(self, expected_pipelines,
                                            actual_pipelines):
        counter = 0
        for actual_pipeline in actual_pipelines:
            self.assertEquals(expected_pipelines[counter],
                              actual_pipeline.RESOURCE_NAME)
            counter += 1

    def _setup_pipeline_builder(self, config_filename):
        inventory_configs = file_loader.read_and_parse_file(
            BASE_PATH + config_filename)
        my_pipeline_builder = pipeline_builder.PipelineBuilder(
            FAKE_TIMESTAMP, inventory_configs, mock.MagicMock(),
            mock.MagicMock(), mock.MagicMock())
        my_pipeline_builder._get_api = mock.MagicMock()
        return my_pipeline_builder

    def testAllEnabled(self):
        my_pipeline_builder = self._setup_pipeline_builder(
            'inventory_all_enabled.yaml')

        actual_runnable_pipelines = my_pipeline_builder.build()

        self.assertEqual(
            len(fake_runnable_pipelines.ALL_ENABLED),
            len(actual_runnable_pipelines))
        self._verify_resource_names_in_pipelines(
            fake_runnable_pipelines.ALL_ENABLED,
            actual_runnable_pipelines)

    def testAllDisabled(self):
        my_pipeline_builder = self._setup_pipeline_builder(
            'inventory_all_disabled.yaml')

        actual_runnable_pipelines = my_pipeline_builder.build()

        self.assertEqual(
            len(fake_runnable_pipelines.ALL_DISABLED),
            len(actual_runnable_pipelines))
        self._verify_resource_names_in_pipelines(
            fake_runnable_pipelines.ALL_DISABLED,
            actual_runnable_pipelines)

    def testOneResourceIsEnabled(self):
        # Enabled: Firewall Rules
        my_pipeline_builder = self._setup_pipeline_builder(
            'inventory_one_resource_is_enabled.yaml')

        actual_runnable_pipelines = my_pipeline_builder.build()

        self.assertEqual(
            len(fake_runnable_pipelines.ONE_RESOURCE_IS_ENABLED),
            len(actual_runnable_pipelines))
        self._verify_resource_names_in_pipelines(
            fake_runnable_pipelines.ONE_RESOURCE_IS_ENABLED,
            actual_runnable_pipelines)

    def testTwoAdjoiningResourcesAreEnabled(self):
        # Enabled: CloudSQL, Firewall Rules
        my_pipeline_builder = self._setup_pipeline_builder(
            'inventory_two_resources_are_enabled.yaml')

        actual_runnable_pipelines = my_pipeline_builder.build()

        self.assertEqual(
            len(fake_runnable_pipelines.TWO_RESOURCES_ARE_ENABLED),
            len(actual_runnable_pipelines))
        self._verify_resource_names_in_pipelines(
            fake_runnable_pipelines.TWO_RESOURCES_ARE_ENABLED,
            actual_runnable_pipelines)

    def testThreeResourcesAreEnabledGroupMembers(self):
        # Enabled: CloudSQL, Firewall Rules, Group Members
        my_pipeline_builder = self._setup_pipeline_builder(
            'inventory_three_resources_are_enabled_group_members.yaml')

        actual_runnable_pipelines = my_pipeline_builder.build()

        self.assertEqual(
            len(fake_runnable_pipelines
                    .THREE_RESOURCES_ARE_ENABLED_GROUP_MEMBERS),
            len(actual_runnable_pipelines))
        self._verify_resource_names_in_pipelines(
            fake_runnable_pipelines.THREE_RESOURCES_ARE_ENABLED_GROUP_MEMBERS,
            actual_runnable_pipelines)

    def testThreeResourcesAreEnabledGroups(self):
        # Enabled: CloudSQL, Firewall Rules, Groups
        my_pipeline_builder = self._setup_pipeline_builder(
            'inventory_three_resources_are_enabled_groups.yaml')

        actual_runnable_pipelines = my_pipeline_builder.build()

        self.assertEqual(
            len(fake_runnable_pipelines.THREE_RESOURCES_ARE_ENABLED_GROUPS),
            len(actual_runnable_pipelines))
        self._verify_resource_names_in_pipelines(
            fake_runnable_pipelines.THREE_RESOURCES_ARE_ENABLED_GROUPS,
            actual_runnable_pipelines)

    def testCoreResourcesAreEnabled(self):
        my_pipeline_builder = self._setup_pipeline_builder(
            'inventory_core_resources_are_enabled.yaml')

        actual_runnable_pipelines = my_pipeline_builder.build()

        self.assertEqual(
            len(fake_runnable_pipelines.CORE_RESOURCES_ARE_ENABLED),
            len(actual_runnable_pipelines))
        self._verify_resource_names_in_pipelines(
            fake_runnable_pipelines.CORE_RESOURCES_ARE_ENABLED,
            actual_runnable_pipelines)

    def testCanGetApiThatIsAlreadyInitialized(self):
        my_pipeline_builder = pipeline_builder.PipelineBuilder(
            FAKE_TIMESTAMP, 'foo_path', mock.MagicMock(),
            api_map.API_MAP, mock.MagicMock())
        my_pipeline_builder.initialized_api_map = {'foo': 'bar'}

        self.assertEquals('bar', my_pipeline_builder._get_api('foo'))

    @mock.patch('google.cloud.security.common.gcp_api.admin_directory.AdminDirectoryClient')
    def testInitializeApiWithEmptyInitializedApiMap(self, mock_admin):
        my_pipeline_builder = pipeline_builder.PipelineBuilder(
            FAKE_TIMESTAMP, 'foo_path', mock.MagicMock(),
            api_map.API_MAP, mock.MagicMock())

        admin_api = my_pipeline_builder._get_api('admin_api')

        self.assertEquals(
            1, len(my_pipeline_builder.initialized_api_map.keys()))
        self.assertTrue('admin_api' in my_pipeline_builder.initialized_api_map)
        self.assertTrue('AdminDirectoryClient()'in str(admin_api))

    @mock.patch('google.cloud.security.common.gcp_api.admin_directory.AdminDirectoryClient')
    def testInitializeApiWithNonEmptyInitializedApiMap(self, mock_admin):
        my_pipeline_builder = pipeline_builder.PipelineBuilder(
            FAKE_TIMESTAMP, 'foo_path', mock.MagicMock(),
            api_map.API_MAP, mock.MagicMock())
        my_pipeline_builder.initialized_api_map = {'foo': 'bar'}

        admin_api = my_pipeline_builder._get_api('admin_api')

        self.assertEquals(
            2, len(my_pipeline_builder.initialized_api_map.keys()))
        self.assertTrue('foo' in my_pipeline_builder.initialized_api_map)
        self.assertEquals('bar', my_pipeline_builder.initialized_api_map['foo'])
        self.assertTrue('admin_api' in my_pipeline_builder.initialized_api_map)
        self.assertTrue('AdminDirectoryClient()'in str(admin_api))


if __name__ == '__main__':
    unittest.main()
