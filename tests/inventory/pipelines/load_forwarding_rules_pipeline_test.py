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

"""Tests the load_forwarding_rules_pipeline."""


from google.apputils import basetest
import mock
import MySQLdb

# pylint: disable=line-too-long
from google.cloud.security.common.data_access import errors as data_access_errors
from google.cloud.security.common.data_access import forwarding_rules_dao as frdao
from google.cloud.security.common.data_access import project_dao
from google.cloud.security.common.gcp_api import compute
from google.cloud.security.common.gcp_api import errors as api_errors
from google.cloud.security.inventory import errors as inventory_errors
from google.cloud.security.inventory.pipelines import load_forwarding_rules_pipeline
from tests.inventory.pipelines.test_data import fake_configs
from tests.inventory.pipelines.test_data import fake_forwarding_rules
from tests.inventory.pipelines.test_data import fake_projects
# pylint: enable=line-too-long


class LoadForwardingRulesPipelineTest(basetest.TestCase):
    """Tests for the load_forwarding_rules_pipeline."""

    def setUp(self):
        """Set up."""
        self.cycle_timestamp = '20001225T120000Z'
        self.configs = fake_configs.FAKE_CONFIGS
        self.resource_name = 'forwarding_rules'
        self.mock_compute_client = mock.create_autospec(compute.ComputeClient)
        self.mock_dao = mock.create_autospec(frdao.ForwardingRulesDao)
        self.pipeline = (
            load_forwarding_rules_pipeline.LoadForwardingRulesPipeline(
                self.cycle_timestamp,
                self.configs,
                self.mock_compute_client,
                self.mock_dao))

        self.project_ids = fake_forwarding_rules \
            .FAKE_PROJECT_FWD_RULES_MAP.keys()
        self.projects = [project_dao.ProjectDao.map_row_to_object(p)
             for p in fake_projects.EXPECTED_LOADABLE_PROJECTS
             if p['project_id'] in self.project_ids]

    def test_can_transform_forwarding_rules(self):
        """Test transform function works."""
        actual = self.pipeline._transform(
            fake_forwarding_rules.FAKE_PROJECT_FWD_RULES_MAP)
        self.assertEquals(
            fake_forwarding_rules.EXPECTED_LOADABLE_FWD_RULES,
            list(actual))

    @mock.patch.object(MySQLdb, 'connect')
    @mock.patch('google.cloud.security.common.data_access.project_dao.ProjectDao.get_projects')
    def test_api_is_called_to_retrieve_forwarding_rules(
            self, mock_get_projects, mock_conn):
        """Test that API is called to retrieve forwarding rules."""
        mock_get_projects.return_value = self.projects
        self.pipeline._retrieve()
        self.assertEqual(
            len(self.project_ids),
            self.pipeline.api_client.get_forwarding_rules.call_count)

    @mock.patch.object(MySQLdb, 'connect')
    @mock.patch('google.cloud.security.common.data_access.project_dao.ProjectDao.get_projects')
    def test_retrieve_data_is_correct(
            self, mock_get_projects, mock_conn):
        """Test _retrieve() data is correct."""
        mock_get_projects.return_value = self.projects

        self.pipeline.api_client.get_forwarding_rules = mock.MagicMock(
            side_effect=[fake_forwarding_rules.FAKE_API_RESPONSE1,
                         fake_forwarding_rules.FAKE_API_RESPONSE2])

        actual = self.pipeline._retrieve()

        self.assertEquals(
            fake_forwarding_rules.FAKE_PROJECT_FWD_RULES_MAP,
            actual)

    @mock.patch.object(MySQLdb, 'connect')
    @mock.patch('google.cloud.security.common.data_access.project_dao.ProjectDao.get_projects')
    def test_retrieve_error_logged_when_api_error(
            self, mock_get_projects, mock_conn):
        """Test that LOGGER.error() is called when there is an API error."""
        mock_get_projects.return_value = self.projects
        self.pipeline.api_client.get_forwarding_rules.side_effect = (
            api_errors.ApiExecutionError(self.resource_name, mock.MagicMock()))
        load_forwarding_rules_pipeline.LOGGER = mock.MagicMock()
        self.pipeline._retrieve()

        self.assertEqual(
            len(self.project_ids),
            load_forwarding_rules_pipeline.LOGGER.error.call_count)

    @mock.patch.object(
        load_forwarding_rules_pipeline.LoadForwardingRulesPipeline,
        '_get_loaded_count')
    @mock.patch.object(
        load_forwarding_rules_pipeline.LoadForwardingRulesPipeline,
        '_load')
    @mock.patch.object(
        load_forwarding_rules_pipeline.LoadForwardingRulesPipeline,
        '_transform')
    @mock.patch.object(
        load_forwarding_rules_pipeline.LoadForwardingRulesPipeline,
        '_retrieve')
    def test_subroutines_are_called_by_run(
            self,
            mock_retrieve,
            mock_transform,
            mock_load,
            mock_get_loaded_count):
        """Test that the subroutines are called by run."""
        mock_retrieve.return_value = \
            fake_forwarding_rules.FAKE_PROJECT_FWD_RULES_MAP
        mock_transform.return_value = (
            fake_forwarding_rules.EXPECTED_LOADABLE_FWD_RULES)
        self.pipeline.run()

        mock_transform.assert_called_once_with(
            fake_forwarding_rules.FAKE_PROJECT_FWD_RULES_MAP)

        self.assertEquals(1, mock_load.call_count)

        # The regular data is loaded.
        called_args, called_kwargs = mock_load.call_args_list[0]
        expected_args = (
            self.pipeline.RESOURCE_NAME,
            fake_forwarding_rules.EXPECTED_LOADABLE_FWD_RULES)
        self.assertEquals(expected_args, called_args)
