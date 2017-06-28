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

"""Tests the load_appengine_pipeline."""

from google.apputils import basetest
import mock
import MySQLdb

# pylint: disable=line-too-long
from google.cloud.security.common.data_access import appengine_dao
from google.cloud.security.common.data_access import errors as data_access_errors
from google.cloud.security.common.data_access import project_dao
from google.cloud.security.common.gcp_api import appengine
from google.cloud.security.common.gcp_api import errors as api_errors
from google.cloud.security.inventory import errors as inventory_errors
from google.cloud.security.inventory.pipelines import base_pipeline
from google.cloud.security.inventory.pipelines import load_appengine_pipeline
from tests.inventory.pipelines.test_data import fake_appengine_applications
from tests.inventory.pipelines.test_data import fake_configs
from tests.inventory.pipelines.test_data import fake_projects
# pylint: enable=line-too-long

class LoadAppenginePipelineTest(basetest.TestCase):
    """Tests for the load_appengine_pipeline."""

    def setUp(self):
        """Set up."""
        self.cycle_timestamp = '20001225T120000Z'
        self.configs = fake_configs.FAKE_CONFIGS
        self.mock_appengine = mock.create_autospec(appengine.AppEngineClient)
        self.mock_dao = mock.create_autospec(appengine_dao.AppEngineDao)
        self.pipeline = (
            load_appengine_pipeline.LoadAppenginePipeline(
                self.cycle_timestamp,
                self.configs,
                self.mock_appengine,
                self.mock_dao))
        self.project_ids = fake_appengine_applications \
            .FAKE_PROJECT_APPLICATIONS_MAP.keys()
        self.projects = [project_dao.ProjectDao.map_row_to_object(p)
             for p in fake_projects.EXPECTED_LOADABLE_PROJECTS
             if p['project_id'] in self.project_ids]

    def test_can_transform_applications(self):
        """Test transform function works."""
        actual = self.pipeline._transform(
            fake_appengine_applications.FAKE_PROJECT_APPLICATIONS_MAP)
        self.assertEquals(
            fake_appengine_applications.EXPECTED_LOADABLE_APPLICATIONS,
            list(actual))

    @mock.patch.object(MySQLdb, 'connect')
    @mock.patch('google.cloud.security.common.data_access.project_dao.ProjectDao.get_projects')
    def test_api_is_called_to_retrieve_applications(
            self, mock_get_projects, mock_conn):
        """Test that API is called to retrieve instances."""
        mock_get_projects.return_value = self.projects
        self.pipeline._retrieve()
        self.assertEqual(
            len(self.project_ids),
            self.pipeline.api_client.get_app.call_count)

    @mock.patch.object(MySQLdb, 'connect')
    @mock.patch('google.cloud.security.common.data_access.project_dao.ProjectDao.get_projects')
    def test_retrieve_data_is_correct(
            self, mock_get_projects, mock_conn):
        """Test _retrieve() data is correct."""
        mock_get_projects.return_value = self.projects
        apps = [fake_appengine_applications.FAKE_PROJECT_APPLICATIONS_MAP[p]
                for p in self.project_ids]

        self.pipeline.api_client.get_app = mock.MagicMock(
            side_effect=apps)

        actual = self.pipeline._retrieve()

        self.assertEquals(
            fake_appengine_applications.FAKE_PROJECT_APPLICATIONS_MAP,
            actual)
