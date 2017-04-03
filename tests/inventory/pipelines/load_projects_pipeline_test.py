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

import json

from google.apputils import basetest
import mock

# pylint: disable=line-too-long
from google.cloud.security.common.data_access import dao
from google.cloud.security.common.data_access import errors as data_access_errors
from google.cloud.security.common.gcp_api import cloud_resource_manager as crm
from google.cloud.security.common.gcp_api import errors as api_errors
from google.cloud.security.common.gcp_type.resource import LifecycleState
from google.cloud.security.inventory import errors as inventory_errors
from google.cloud.security.inventory.pipelines import load_projects_pipeline
from tests.inventory.pipelines.test_data.fake_projects import EXPECTED_FLATTENED_PROJECTS
from tests.inventory.pipelines.test_data.fake_projects import FAKE_PROJECTS
# pylint: enable=line-too-long


class LoadProjectsPipelineTest(basetest.TestCase):
    """Tests for the load_org_iam_policies_pipeline."""

    def setUp(self):
        """Set up."""
        self.cycle_timestamp = '20001225T120000Z'
        self.configs = {'organization_id': '660570133860',
                        'max_crm_api_calls_per_100_seconds': 400,
                        'db_name': 'forseti_security',
                        'db_user': 'sqlproxy',
                        'db_host': '127.0.0.1',
                        'email_sender': 'foo.sender@company.com', 
                        'email_recipient': 'foo.recipient@company.com',
                        'sendgrid_api_key': 'foo_email_key',}
        self.mock_crm = mock.create_autospec(crm.CloudResourceManagerClient)
        self.mock_dao = mock.create_autospec(dao.Dao)
        self.pipeline = (
            load_projects_pipeline.LoadProjectsPipeline(
                self.cycle_timestamp,
                self.configs,
                self.mock_crm,
                self.mock_dao))

    def test_data_are_loaded(self):
        """Test that data are loaded."""
        self.pipeline._load(EXPECTED_FLATTENED_PROJECTS)

        self.mock_dao.load_data.assert_called_once_with(
            self.pipeline.name,
            self.pipeline.cycle_timestamp,
            EXPECTED_FLATTENED_PROJECTS)

    def test_exceptions_are_handled_when_loading(self):
        """Test that exceptions are handled when loading."""

        self.pipeline.dao.load_data.side_effect = (
            data_access_errors.MySQLError('11111', '22222'))
        self.assertRaises(inventory_errors.LoadDataPipelineError,
                          self.pipeline._load,
                          EXPECTED_FLATTENED_PROJECTS)

    def test_can_flatten_projects(self):
        """Test that projects can be flattened."""

        projects = self.pipeline._flatten(FAKE_PROJECTS)
        for (i, project) in enumerate(projects):
            # Normalize to python representation.
            project['raw_project'] = json.loads(project['raw_project'])
            project = json.loads(json.dumps(project))
            self.assertEquals(EXPECTED_FLATTENED_PROJECTS[i], project)

    def test_api_is_called_to_retrieve_projects(self):
        """Test that api is called to retrieve projects."""
        self.pipeline._retrieve(self.pipeline.configs['organization_id'])

        self.mock_crm.get_projects.assert_called_once_with(
            self.pipeline.name,
            self.pipeline.configs['organization_id'],
            lifecycleState=LifecycleState.ACTIVE)

    def test_exceptions_are_handled_when_retrieving(self):
        """Test that exceptions are handled when retrieving."""

        self.pipeline.gcp_api_client.get_projects.side_effect = (
            api_errors.ApiExecutionError('11111', mock.MagicMock()))

        self.assertRaises(inventory_errors.LoadDataPipelineError,
                          self.pipeline._retrieve,
                          self.pipeline.configs['organization_id'])

    @mock.patch.object(
        load_projects_pipeline.LoadProjectsPipeline,
        '_get_loaded_count')
    @mock.patch.object(
        load_projects_pipeline.LoadProjectsPipeline,
        '_load')    
    @mock.patch.object(
        load_projects_pipeline.LoadProjectsPipeline,
        '_flatten')
    @mock.patch.object(
        load_projects_pipeline.LoadProjectsPipeline,
        '_retrieve')
    def test_subroutines_are_called_by_run(self, mock_retrieve, mock_flatten,
            mock_load, mock_get_loaded_count):
        """Test that the subroutines are called by run."""

        mock_retrieve.return_value = FAKE_PROJECTS
        mock_flatten.return_value = EXPECTED_FLATTENED_PROJECTS
        self.pipeline.run()

        mock_retrieve.assert_called_once_with(
            self.configs.get('organization_id'))

        mock_flatten.assert_called_once_with(FAKE_PROJECTS)

        mock_load.assert_called_once_with(EXPECTED_FLATTENED_PROJECTS)
        
        mock_get_loaded_count.assert_called_once

