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

"""Tests the load_groups_pipeline."""

import json

from tests.unittest_utils import ForsetiTestCase
import mock
import unittest

# pylint: disable=line-too-long
from google.cloud.security.common.data_access import dao
from google.cloud.security.common.data_access import errors as data_access_errors
from google.cloud.security.common.gcp_api import admin_directory as ad
from google.cloud.security.common.gcp_api import errors as api_errors
from google.cloud.security.common.gcp_type.resource import LifecycleState
from google.cloud.security.inventory import errors as inventory_errors
from google.cloud.security.inventory.pipelines import load_groups_pipeline
from google.cloud.security.inventory import util
from tests.inventory.pipelines.test_data import fake_configs
from tests.inventory.pipelines.test_data import fake_groups
# pylint: enable=line-too-long


class LoadGroupsPipelineTest(ForsetiTestCase):
    """Tests for the load_groups_pipeline."""

    def setUp(self):
        """Set up."""

        self.cycle_timestamp = '20001225T120000Z'
        self.configs = fake_configs.FAKE_CONFIGS
        self.mock_admin_client = mock.create_autospec(ad.AdminDirectoryClient)
        self.mock_dao = mock.create_autospec(dao.Dao)
        self.pipeline = (
            load_groups_pipeline.LoadGroupsPipeline(
                self.cycle_timestamp,
                self.configs,
                self.mock_admin_client,
                self.mock_dao))

    def test_can_transform_groups(self):
        """Test that groups can be transformed."""

        groups = self.pipeline._transform(fake_groups.FAKE_GROUPS)
        for (i, group) in enumerate(groups):
            self.assertDictEqual(fake_groups.EXPECTED_LOADABLE_GROUPS[i], group)

    def test_api_is_called_to_retrieve_groups(self):
        """Test that api is called to retrieve projects."""

        self.pipeline._retrieve()

        self.pipeline.api_client.get_groups.assert_called_once_with()

    def test_retrieve_errors_are_handled(self):
        """Test that errors are handled when retrieving."""

        self.pipeline.api_client.get_groups.side_effect = (
            api_errors.ApiExecutionError('11111', mock.MagicMock()))

        with self.assertRaises(inventory_errors.LoadDataPipelineError):
            self.pipeline._retrieve()

    @mock.patch.object(
        util, 'can_inventory_groups')
    @mock.patch.object(
        load_groups_pipeline.LoadGroupsPipeline,
        '_get_loaded_count')
    @mock.patch.object(
        load_groups_pipeline.LoadGroupsPipeline,
        '_load')
    @mock.patch.object(
        load_groups_pipeline.LoadGroupsPipeline,
        '_transform')
    @mock.patch.object(
        load_groups_pipeline.LoadGroupsPipeline,
        '_retrieve')
    def test_subroutines_are_called_by_run(self, mock_retrieve, mock_transform,
            mock_load, mock_get_loaded_count, mock_can_inventory_groups):
        """Test that the subroutines are called by run."""

        mock_can_inventory_groups.return_value = True
        mock_retrieve.return_value = fake_groups.FAKE_GROUPS
        mock_transform.return_value = fake_groups.EXPECTED_LOADABLE_GROUPS
        self.pipeline.run()

        mock_retrieve.assert_called_once_with()

        mock_transform.assert_called_once_with(fake_groups.FAKE_GROUPS)

        mock_load.assert_called_once_with(
            self.pipeline.RESOURCE_NAME,
            fake_groups.EXPECTED_LOADABLE_GROUPS)

        mock_get_loaded_count.assert_called_once


if __name__ == '__main__':
      unittest.main()
