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

"""Tests the load_gke_pipeline."""

import mock
import MySQLdb
import unittest

# pylint: disable=line-too-long
from tests.unittest_utils import ForsetiTestCase
from google.cloud.security.common.data_access import project_dao
from google.cloud.security.common.gcp_api import container
from google.cloud.security.inventory.pipelines import load_gke_pipeline
from tests.inventory.pipelines.test_data import fake_gke_services
from tests.inventory.pipelines.test_data import fake_configs
from tests.inventory.pipelines.test_data import fake_projects
# pylint: enable=line-too-long


class LoadGkePipelineTest(ForsetiTestCase):
    """Tests for the load_gke_pipeline."""

    def setUp(self):
        """Set up."""
        self.cycle_timestamp = '20001225T120000Z'
        self.configs = fake_configs.FAKE_CONFIGS
        self.mock_gke = mock.create_autospec(container.ContainerClient)
        self.mock_dao = mock.MagicMock()
        self.pipeline = (
            load_gke_pipeline.LoadGkePipeline(
                self.cycle_timestamp,
                self.configs,
                self.mock_gke,
                self.mock_dao))
        self.project_ids = fake_gke_services.FAKE_GKE_SERVICES_MAP.keys()
        self.projects = [project_dao.ProjectDao.map_row_to_object(p)
             for p in fake_projects.EXPECTED_LOADABLE_PROJECTS
             if p['project_id'] in self.project_ids]

    def test_can_transform_gke_services(self):
        """Test transform function works."""
        actual = self.pipeline._transform(
            fake_gke_services.FAKE_GKE_SERVICES_MAP)
        self.assertEquals(
            fake_gke_services.EXPECTED_LOADABLE_GKE_SERVICES,
            list(actual))

    @mock.patch.object(MySQLdb, 'connect')
    @mock.patch('google.cloud.security.inventory.pipelines.base_pipeline.BasePipeline.safe_api_call')
    @mock.patch('google.cloud.security.common.data_access.project_dao.ProjectDao.get_projects')
    def test_retrieve_data_is_correct(
            self, mock_get_projects, mock_safe_api_call, mock_conn):
        """Test _retrieve() data is correct."""
        mock_get_projects.return_value = self.projects
        apps = [fake_gke_services.FAKE_GKE_SERVICES_MAP[p]
                for p in self.project_ids]

        mock_safe_api_call.side_effect = [apps[0],
                                          fake_gke_services.FAKE_SERVER_CONFIG]

        actual_gke_services = self.pipeline._retrieve()

        self.assertEquals(
            fake_gke_services.FAKE_GKE_SERVICES_MAP,
            actual_gke_services)

    @mock.patch.object(
        load_gke_pipeline.LoadGkePipeline, '_get_loaded_count')
    @mock.patch.object(load_gke_pipeline.LoadGkePipeline, '_load')
    @mock.patch.object(load_gke_pipeline.LoadGkePipeline, '_transform')
    @mock.patch.object(load_gke_pipeline.LoadGkePipeline, '_retrieve')
    def test_subroutines_are_called_by_run(
            self,
            mock_retrieve,
            mock_transform,
            mock_load,
            mock_get_loaded_count):
        """Test that the subroutines are called by run."""
        mock_retrieve.return_value = (
            fake_gke_services.FAKE_GKE_SERVICES_MAP)
        mock_transform.return_value = (
            fake_gke_services.EXPECTED_LOADABLE_GKE_SERVICES)
        self.pipeline.run()

        mock_transform.assert_called_once_with(
            fake_gke_services.FAKE_GKE_SERVICES_MAP)

        self.assertEquals(1, mock_load.call_count)

        # The regular data is loaded.
        called_args, called_kwargs = mock_load.call_args_list[0]
        expected_args = (
            self.pipeline.RESOURCE_NAME,
            fake_gke_services.EXPECTED_LOADABLE_GKE_SERVICES)
        self.assertEquals(expected_args, called_args)


if __name__ == '__main__':
      unittest.main()
