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

from google.apputils import basetest
import mock

from google.cloud.security.common.util import file_loader
from tests.inventory.test_data import fake_runnable_pipelines


from google.cloud.security.inventory import pipeline_builder


BASE_PATH = 'tests/inventory/test_data/'
FAKE_TIMESTAMP = '20001225T121212Z'

class PipelineBuilderTest(basetest.TestCase):
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

    def testAllEnabled(self):
        config_path = BASE_PATH + 'inventory_all_enabled.yaml'
        my_pipeline_builder = pipeline_builder.PipelineBuilder(
            FAKE_TIMESTAMP, config_path, mock.MagicMock(),
            mock.MagicMock(), mock.MagicMock())

        actual_runnable_pipelines = my_pipeline_builder.build()
        
        self.assertEqual(
            len(fake_runnable_pipelines.ALL_ENABLED),
            len(actual_runnable_pipelines))
        self._verify_resource_names_in_pipelines(
            fake_runnable_pipelines.ALL_ENABLED,
            actual_runnable_pipelines)
        
    def testAllDisabled(self):
        config_path = BASE_PATH + 'inventory_all_disabled.yaml'
        my_pipeline_builder = pipeline_builder.PipelineBuilder(
            FAKE_TIMESTAMP, config_path, mock.MagicMock(),
            mock.MagicMock(), mock.MagicMock())

        actual_runnable_pipelines = my_pipeline_builder.build()
        
        self.assertEqual(
            len(fake_runnable_pipelines.ALL_DISABLED),
            len(actual_runnable_pipelines))
        self._verify_resource_names_in_pipelines(
            fake_runnable_pipelines.ALL_DISABLED,
            actual_runnable_pipelines)

    def testOneResourceIsEnabled(self):
        # Enabled: Firewall Rules
        config_path = BASE_PATH + 'inventory_one_resource_is_enabled.yaml'
        my_pipeline_builder = pipeline_builder.PipelineBuilder(
            FAKE_TIMESTAMP, config_path, mock.MagicMock(),
            mock.MagicMock(), mock.MagicMock())

        actual_runnable_pipelines = my_pipeline_builder.build()
        
        self.assertEqual(
            len(fake_runnable_pipelines.ONE_RESOURCE_IS_ENABLED),
            len(actual_runnable_pipelines))
        self._verify_resource_names_in_pipelines(
            fake_runnable_pipelines.ONE_RESOURCE_IS_ENABLED,
            actual_runnable_pipelines)

    def testTwoAdjoiningResourcesAreEnabled(self):
        # Enabled: CloudSQL, Firewall Rules
        config_path = BASE_PATH + 'inventory_two_resources_are_enabled.yaml'
        my_pipeline_builder = pipeline_builder.PipelineBuilder(
            FAKE_TIMESTAMP, config_path, mock.MagicMock(),
            mock.MagicMock(), mock.MagicMock())

        actual_runnable_pipelines = my_pipeline_builder.build()
        
        self.assertEqual(
            len(fake_runnable_pipelines.TWO_RESOURCES_ARE_ENABLED),
            len(actual_runnable_pipelines))
        self._verify_resource_names_in_pipelines(
            fake_runnable_pipelines.TWO_RESOURCES_ARE_ENABLED,
            actual_runnable_pipelines)

    def testThreeResourcesAreEnabledGroupMembers(self):
        # Enabled: CloudSQL, Firewall Rules, Group Members
        config_path = (BASE_PATH +
            'inventory_three_resources_are_enabled_group_members.yaml')
        my_pipeline_builder = pipeline_builder.PipelineBuilder(
            FAKE_TIMESTAMP, config_path, mock.MagicMock(),
            mock.MagicMock(), mock.MagicMock())

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
        config_path = (BASE_PATH +
            'inventory_three_resources_are_enabled_groups.yaml')
        my_pipeline_builder = pipeline_builder.PipelineBuilder(
            FAKE_TIMESTAMP, config_path, mock.MagicMock(),
            mock.MagicMock(), mock.MagicMock())

        actual_runnable_pipelines = my_pipeline_builder.build()
        
        self.assertEqual(
            len(fake_runnable_pipelines.THREE_RESOURCES_ARE_ENABLED_GROUPS),
            len(actual_runnable_pipelines))
        self._verify_resource_names_in_pipelines(
            fake_runnable_pipelines.THREE_RESOURCES_ARE_ENABLED_GROUPS,
            actual_runnable_pipelines)

    def testCoreResourcesAreEnabled(self):
        config_path = (BASE_PATH +
            'inventory_core_resources_are_enabled.yaml')
        my_pipeline_builder = pipeline_builder.PipelineBuilder(
            FAKE_TIMESTAMP, config_path, mock.MagicMock(),
            mock.MagicMock(), mock.MagicMock())

        actual_runnable_pipelines = my_pipeline_builder.build()
        
        self.assertEqual(
            len(fake_runnable_pipelines.CORE_RESOURCES_ARE_ENABLED),
            len(actual_runnable_pipelines))
        self._verify_resource_names_in_pipelines(
            fake_runnable_pipelines.CORE_RESOURCES_ARE_ENABLED,
            actual_runnable_pipelines)
