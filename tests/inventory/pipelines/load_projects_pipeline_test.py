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

"""Tests the load_projects_pipeline."""

from google.apputils import basetest
import mock
import gflags as flags
import sys


# pylint: disable=line-too-long
from google.cloud.security.common.data_access import errors as data_access_errors
from google.cloud.security.common.data_access import project_dao as proj_dao
from google.cloud.security.common.gcp_api import cloud_resource_manager as crm
from google.cloud.security.common.gcp_api import errors as api_errors
from google.cloud.security.common.gcp_type.resource import LifecycleState
from google.cloud.security.inventory import errors as inventory_errors
from google.cloud.security.inventory.pipelines import load_projects_pipeline
from tests.inventory.pipelines.test_data import fake_configs
from tests.inventory.pipelines.test_data import fake_projects
# pylint: enable=line-too-long

FLAGS = flags.FLAGS
FLAGS(sys.argv)


class LoadProjectsPipelineTest(basetest.TestCase):
    """Tests for the load_projects_pipeline."""

    def setUp(self):
        """Set up."""
        self.cycle_timestamp = '20001225T120000Z'
        self.configs = fake_configs.FAKE_CONFIGS
        self.mock_crm = mock.create_autospec(crm.CloudResourceManagerClient)
        self.mock_dao = mock.create_autospec(proj_dao.ProjectDao)
        load_projects_pipeline.LOGGER = mock.MagicMock()
        self.pipeline = (
            load_projects_pipeline.LoadProjectsPipeline(
                self.cycle_timestamp,
                self.configs,
                self.mock_crm,
                self.mock_dao))

    def test_can_transform_projects(self):
        """Test that projects can be transformed."""

        project = list(self.pipeline._transform(fake_projects.FAKE_PROJECTS))
        self.assertEquals(
            fake_projects.EXPECTED_LOADABLE_PROJECTS, project)

    def test_api_is_called_to_retrieve_projects(self):
        """Test that api is called to retrieve projects."""

        self.pipeline._retrieve()

        self.pipeline.api_client.get_projects.assert_called_once_with(
            self.pipeline.RESOURCE_NAME,
            lifecycleState=LifecycleState.ACTIVE)

    def test_retrieve_errors_are_handled(self):
        """Test that errors are handled when retrieving."""

        self.pipeline.api_client.get_projects.side_effect = (
            api_errors.ApiExecutionError('11111', mock.MagicMock()))

        with self.assertRaises(inventory_errors.LoadDataPipelineError):
            self.pipeline._retrieve()

    @mock.patch.object(
        load_projects_pipeline.LoadProjectsPipeline,
        '_get_loaded_count')
    @mock.patch.object(
        load_projects_pipeline.LoadProjectsPipeline,
        '_load')    
    @mock.patch.object(
        load_projects_pipeline.LoadProjectsPipeline,
        '_transform')
    @mock.patch.object(
        load_projects_pipeline.LoadProjectsPipeline,
        '_retrieve')
    def test_subroutines_are_called_by_run(self, mock_retrieve, mock_transform,
            mock_load, mock_get_loaded_count):
        """Test that the subroutines are called by run."""

        mock_retrieve.return_value = fake_projects.FAKE_PROJECTS
        mock_transform.return_value = fake_projects.EXPECTED_LOADABLE_PROJECTS
        self.pipeline.run()

        mock_retrieve.assert_called_once_with()

        mock_transform.assert_called_once_with(fake_projects.FAKE_PROJECTS)

        mock_load.assert_called_once_with(
            self.pipeline.RESOURCE_NAME,
            fake_projects.EXPECTED_LOADABLE_PROJECTS)
        
        mock_get_loaded_count.assert_called_once
