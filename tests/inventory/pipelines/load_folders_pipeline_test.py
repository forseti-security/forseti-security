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

"""Tests the load_folders_pipeline."""

from tests.unittest_utils import ForsetiTestCase
import json
import mock

# pylint: disable=line-too-long
from google.cloud.security.common.data_access import errors as data_access_errors
from google.cloud.security.common.data_access import folder_dao
from google.cloud.security.common.gcp_api import cloud_resource_manager as crm
from google.cloud.security.common.gcp_api import errors as api_errors
from google.cloud.security.inventory import errors as inventory_errors
from google.cloud.security.inventory.pipelines import load_folders_pipeline
from tests.inventory.pipelines.test_data import fake_configs
from tests.inventory.pipelines.test_data import fake_folders
# pylint: enable=line-too-long

def _setup_raw_folders():
    fakes = [o for res in fake_folders.FAKE_FOLDERS \
        for o in res.get('folders', [])]
    for (i, o) in enumerate(fake_folders.EXPECTED_LOADABLE_FOLDERS):
        fake_folders.EXPECTED_LOADABLE_FOLDERS[i]['raw_folder'] = \
            json.dumps(fakes[i])

class LoadFoldersPipelineTest(ForsetiTestCase):
    """Tests for the load_folders_pipeline."""

    @classmethod
    def setUpClass(cls):
        """Set up before running the class tests."""
        _setup_raw_folders()

    def setUp(self):
        """Set up."""
        self.cycle_timestamp = '20001225T120000Z'
        self.configs = fake_configs.FAKE_CONFIGS
        self.mock_crm = mock.create_autospec(crm.CloudResourceManagerClient)
        self.mock_dao = mock.create_autospec(folder_dao.FolderDao)
        self.pipeline = (
            load_folders_pipeline.LoadFoldersPipeline(
                self.cycle_timestamp,
                self.configs,
                self.mock_crm,
                self.mock_dao))

    def test_can_transform_folders(self):
        """Test that folders can be transformed."""

        folders = list(self.pipeline._transform(fake_folders.FAKE_FOLDERS))
        self.assertEquals(fake_folders.EXPECTED_LOADABLE_FOLDERS, folders)

    def test_api_is_called_to_retrieve_folders(self):
        """Test that api is called to retrieve folders."""

        self.pipeline._retrieve()

        self.pipeline.api_client.get_folders.assert_called_once_with(
            self.pipeline.RESOURCE_NAME)

    def test_retrieve_errors_are_handled(self):
        """Test that errors are handled when retrieving."""

        self.pipeline.api_client.get_folders.side_effect = (
            api_errors.ApiExecutionError('11111', mock.MagicMock()))

        with self.assertRaises(inventory_errors.LoadDataPipelineError):
            self.pipeline._retrieve()

    @mock.patch.object(
        load_folders_pipeline.LoadFoldersPipeline,
        '_get_loaded_count')
    @mock.patch.object(
        load_folders_pipeline.LoadFoldersPipeline,
        '_load')    
    @mock.patch.object(
        load_folders_pipeline.LoadFoldersPipeline,
        '_transform')
    @mock.patch.object(
        load_folders_pipeline.LoadFoldersPipeline,
        '_retrieve')
    def test_subroutines_are_called_by_run(self, mock_retrieve, mock_transform,
            mock_load, mock_get_loaded_count):
        """Test that the subroutines are called by run."""

        mock_retrieve.return_value = fake_folders.FAKE_FOLDERS
        mock_transform.return_value = fake_folders.EXPECTED_LOADABLE_FOLDERS
        self.pipeline.run()

        mock_retrieve.assert_called_once_with()

        mock_transform.assert_called_once_with(fake_folders.FAKE_FOLDERS)

        mock_load.assert_called_once_with(
            self.pipeline.RESOURCE_NAME,
            fake_folders.EXPECTED_LOADABLE_FOLDERS)
        
        mock_get_loaded_count.assert_called_once
