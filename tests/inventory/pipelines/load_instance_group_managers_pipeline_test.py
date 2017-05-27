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

"""Tests the load_instance_group_managers_pipeline."""

from google.apputils import basetest
import mock
import MySQLdb

# pylint: disable=line-too-long
from google.cloud.security.common.data_access import errors as data_access_errors
from google.cloud.security.common.data_access import instance_group_manager_dao
from google.cloud.security.common.data_access import project_dao
from google.cloud.security.common.gcp_api import compute
from google.cloud.security.common.gcp_api import errors as api_errors
from google.cloud.security.inventory import errors as inventory_errors
from google.cloud.security.inventory.pipelines import base_pipeline
from google.cloud.security.inventory.pipelines import load_instance_group_managers_pipeline
from tests.inventory.pipelines.test_data import fake_configs
from tests.inventory.pipelines.test_data import fake_instance_group_managers
from tests.inventory.pipelines.test_data import fake_projects
# pylint: enable=line-too-long


def _set_count(*args, **kwargs):
    """Set the pipeline count."""


class LoadInstanceGroupManagersPipelineTest(basetest.TestCase):
    """Tests for the load_instance_group_managers_pipeline."""

    def setUp(self):
        """Set up."""
        self.cycle_timestamp = '20001225T120000Z'
        self.configs = fake_configs.FAKE_CONFIGS
        self.resource_name = 'instance_group_managers'
        self.maxDiff = None
        self.mock_compute_client = mock.create_autospec(compute.ComputeClient)
        self.mock_dao = mock.create_autospec(instance_group_manager_dao.InstanceGroupManagerDao)
        self.pipeline = (
            load_instance_group_managers_pipeline.LoadInstanceGroupManagersPipeline(
                self.cycle_timestamp,
                self.configs,
                self.mock_compute_client,
                self.mock_dao))

        self.project_ids = fake_instance_group_managers \
            .FAKE_PROJECT_INSTANCE_GROUP_MANAGERS_MAP.keys()
        self.projects = [project_dao.ProjectDao.map_row_to_object(p)
             for p in fake_projects.EXPECTED_LOADABLE_PROJECTS
             if p['project_id'] in self.project_ids]

    def test_can_transform_instance_group_managers(self):
        """Test transform function works."""
        actual = self.pipeline._transform(
            fake_instance_group_managers.FAKE_PROJECT_INSTANCE_GROUP_MANAGERS_MAP)
        self.assertEquals(
            fake_instance_group_managers.EXPECTED_LOADABLE_INSTANCE_GROUP_MANAGERS,
            list(actual))

    @mock.patch.object(MySQLdb, 'connect')
    @mock.patch('google.cloud.security.common.data_access.project_dao.ProjectDao.get_projects')
    def test_api_is_called_to_retrieve_instance_group_managers(
            self, mock_get_projects, mock_conn):
        """Test that API is called to retrieve instance_group_managers."""
        mock_get_projects.return_value = self.projects
        self.pipeline._retrieve()
        self.assertEqual(
            len(self.project_ids),
            self.pipeline.api_client.get_instance_group_managers.call_count)

    @mock.patch.object(MySQLdb, 'connect')
    @mock.patch('google.cloud.security.common.data_access.project_dao.ProjectDao.get_projects')
    def test_retrieve_data_is_correct(
            self, mock_get_projects, mock_conn):
        """Test _retrieve() data is correct."""
        mock_get_projects.return_value = self.projects

        self.pipeline.api_client.get_instance_group_managers = mock.MagicMock(
            side_effect=[fake_instance_group_managers.FAKE_API_RESPONSE1,
                         fake_instance_group_managers.FAKE_API_RESPONSE2])

        actual = self.pipeline._retrieve()

        self.assertEquals(
            fake_instance_group_managers.FAKE_PROJECT_INSTANCE_GROUP_MANAGERS_MAP,
            actual)

    @mock.patch.object(MySQLdb, 'connect')
    @mock.patch('google.cloud.security.common.data_access.project_dao.ProjectDao.get_projects')
    def test_retrieve_error_logged_when_api_error(
            self, mock_get_projects, mock_conn):
        """Test that LOGGER.error() is called when there is an API error."""
        mock_get_projects.return_value = self.projects
        self.pipeline.api_client.get_instance_group_managers.side_effect = (
            api_errors.ApiExecutionError(self.resource_name, mock.MagicMock()))
        load_instance_group_managers_pipeline.LOGGER = mock.MagicMock()
        self.pipeline._retrieve()

        self.assertEqual(
            len(self.project_ids),
            load_instance_group_managers_pipeline.LOGGER.error.call_count)

    @mock.patch.object(MySQLdb, 'connect')
    @mock.patch('google.cloud.security.common.data_access.project_dao.ProjectDao.get_projects')
    def test_pipeline_no_rules_loads_nothing(
            self, mock_get_projects, mock_conn):
        """Test the pipeline with no instance_group_managers."""
        mock_get_projects.return_value = self.projects
        base_pipeline.LOGGER = mock.MagicMock()
        self.pipeline.api_client.get_instance_group_managers = mock.MagicMock(
            side_effect=[[], []])
        self.pipeline.dao.select_record_count = mock.MagicMock(
            side_effect=data_access_errors.MySQLError(
                'instance_group_managers', mock.MagicMock()))

        self.pipeline.run()

        self.assertEquals(None, self.pipeline.count)

    @mock.patch.object(
        load_instance_group_managers_pipeline.LoadInstanceGroupManagersPipeline,
        '_get_loaded_count')
    @mock.patch.object(
        load_instance_group_managers_pipeline.LoadInstanceGroupManagersPipeline,
        '_load')
    @mock.patch.object(
        load_instance_group_managers_pipeline.LoadInstanceGroupManagersPipeline,
        '_transform')
    @mock.patch.object(
        load_instance_group_managers_pipeline.LoadInstanceGroupManagersPipeline,
        '_retrieve')
    def test_subroutines_are_called_by_run(
            self,
            mock_retrieve,
            mock_transform,
            mock_load,
            mock_get_loaded_count):
        """Test that the subroutines are called by run."""
        mock_retrieve.return_value = \
            fake_instance_group_managers.FAKE_PROJECT_INSTANCE_GROUP_MANAGERS_MAP
        mock_transform.return_value = (
            fake_instance_group_managers.EXPECTED_LOADABLE_INSTANCE_GROUP_MANAGERS)
        self.pipeline.run()

        mock_transform.assert_called_once_with(
            fake_instance_group_managers.FAKE_PROJECT_INSTANCE_GROUP_MANAGERS_MAP)

        self.assertEquals(1, mock_load.call_count)

        # The regular data is loaded.
        called_args, called_kwargs = mock_load.call_args_list[0]
        expected_args = (
            self.pipeline.RESOURCE_NAME,
            fake_instance_group_managers.EXPECTED_LOADABLE_INSTANCE_GROUP_MANAGERS)
        self.assertEquals(expected_args, called_args)
