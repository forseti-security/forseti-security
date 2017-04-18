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

"""Tests the load_group_members_pipeline."""

import json

from google.apputils import basetest
import mock

# pylint: disable=line-too-long
from google.cloud.security.common.data_access import dao
from google.cloud.security.common.data_access import errors as data_access_errors
from google.cloud.security.common.gcp_api import admin_directory as ad
from google.cloud.security.common.gcp_api import errors as api_errors
from google.cloud.security.common.gcp_type.resource import LifecycleState
from google.cloud.security.inventory import errors as inventory_errors
from google.cloud.security.inventory.pipelines import load_group_members_pipeline
from google.cloud.security.inventory import util as inventory_util
from tests.inventory.pipelines.test_data import fake_configs
from tests.inventory.pipelines.test_data import fake_group_members
# pylint: enable=line-too-long


class LoadGroupMembersPipelineTest(basetest.TestCase):
    """Tests for the load_group_members pipeline."""

    def setUp(self):
        """Set up."""

        self.RESOURCE_NAME = 'group_members'
        self.cycle_timestamp = '20001225T120000Z'
        self.configs = fake_configs.FAKE_CONFIGS
        self.mock_admin_client = mock.create_autospec(ad.AdminDirectoryClient)
        self.mock_dao = mock.create_autospec(dao.Dao)
        self.pipeline = (
            load_group_members_pipeline.LoadGroupMembersPipeline(
                self.cycle_timestamp,
                self.configs,
                self.mock_admin_client,
                self.mock_dao))

    def test_can_transform_group_members(self):
        """Test that group members can be transformed."""

        loadable_groups_members = self.pipeline._transform(
            fake_group_members.FAKE_GROUPS_MEMBERS_MAP)
        for (i, group_member) in enumerate(loadable_groups_members):            
            self.assertDictEqual(
                fake_group_members.EXPECTED_LOADABLE_GROUP_MEMBERS[i],
                group_member)

    @mock.patch.object(
        load_group_members_pipeline.LoadGroupMembersPipeline,
        '_fetch_groups_from_dao')
    def test_api_is_called_to_retrieve_groups(self, mock_dao_fetch):
        """Test that api is called to retrieve projects."""
        mock_dao_fetch.return_value = 'a'

        self.pipeline._retrieve()
        self.pipeline.api_client.get_group_members.assert_called_with('a')

    @mock.patch.object(
        inventory_util, 'can_inventory_groups')
    @mock.patch.object(
        load_group_members_pipeline.LoadGroupMembersPipeline,
        '_get_loaded_count')
    @mock.patch.object(
        load_group_members_pipeline.LoadGroupMembersPipeline,
        '_load')
    @mock.patch.object(
        load_group_members_pipeline.LoadGroupMembersPipeline,
        '_transform')
    @mock.patch.object(
        load_group_members_pipeline.LoadGroupMembersPipeline,
        '_retrieve')
    def test_subroutines_are_called_by_run(self, mock_retrieve, mock_transform,
            mock_load, mock_get_loaded_count, mock_can_inventory_groups):
        """Test that the subroutines are called by run."""

        mock_can_inventory_groups.return_value = True
        mock_retrieve.return_value = fake_group_members.FAKE_GROUPS_MEMBERS_MAP
        mock_transform.return_value = fake_group_members.EXPECTED_LOADABLE_GROUP_MEMBERS
        self.pipeline.run()

        mock_retrieve.assert_called_once_with()

        mock_transform.assert_called_once_with(fake_group_members.FAKE_GROUPS_MEMBERS_MAP)

        mock_load.assert_called_once_with(
            self.pipeline.RESOURCE_NAME,
            fake_group_members.EXPECTED_LOADABLE_GROUP_MEMBERS)

        mock_get_loaded_count.assert_called_once
