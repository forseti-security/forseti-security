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

"""Tests the load_service_accounts_pipeline."""

import MySQLdb
import mock
import unittest

from google.cloud.security.common.data_access import project_dao
from google.cloud.security.common.data_access import service_account_dao
from google.cloud.security.common.gcp_api import iam
from google.cloud.security.inventory.pipelines import \
    load_service_accounts_pipeline
from tests.inventory.pipelines.test_data import fake_service_accounts
from tests.inventory.pipelines.test_data import fake_configs
from tests.inventory.pipelines.test_data import fake_projects
# pylint: disable=line-too-long
from tests.unittest_utils import ForsetiTestCase


# pylint: enable=line-too-long


class LoadServiceAccountsPipelineTest(ForsetiTestCase):
    """Tests for the load_service_accounts_pipeline."""

    def setUp(self):
        """Set up."""
        self.cycle_timestamp = '20001225T120000Z'
        self.configs = fake_configs.FAKE_CONFIGS
        self.mock_iam = mock.create_autospec(iam.IAMClient)
        self.mock_dao = mock.create_autospec(
            service_account_dao.ServiceAccountDao)
        self.pipeline = (
            load_service_accounts_pipeline.LoadServiceAccountsPipeline(
                self.cycle_timestamp,
                self.configs,
                self.mock_iam,
                self.mock_dao))
        self.project_ids = fake_service_accounts \
            .FAKE_PROJECT_SERVICE_ACCOUNTS_MAP.keys()
        self.projects = [project_dao.ProjectDao.map_row_to_object(p)
                         for p in fake_projects.EXPECTED_LOADABLE_PROJECTS
                         if p['project_id'] in self.project_ids]

    def test_can_transform_service_accounts(self):
        """Test transform function works."""
        actual = self.pipeline._transform(
            fake_service_accounts.FAKE_PROJECT_SERVICE_ACCOUNTS_MAP_WITH_KEYS)
        self.assertEquals(
            fake_service_accounts.EXPECTED_LOADABLE_SERVICE_ACCOUNTS,
            list(actual))

    @mock.patch.object(MySQLdb, 'connect')
    @mock.patch('google.cloud.security.common.data_access.project_dao.ProjectDao.get_projects')
    def test_api_is_called_to_retrieve_service_accounts(
            self, mock_get_projects, mock_conn):
        """Test that API is called to retrieve instances."""
        mock_get_projects.return_value = self.projects
        self.pipeline._retrieve()
        self.assertEqual(
            len(self.project_ids),
            self.pipeline.api_client.get_service_accounts.call_count)

    @mock.patch.object(MySQLdb, 'connect')
    @mock.patch('google.cloud.security.common.data_access.project_dao.ProjectDao.get_projects')
    def test_retrieve_data_is_correct(
            self, mock_get_projects, mock_conn):
        """Test _retrieve() data is correct."""
        mock_get_projects.return_value = self.projects
        service_accounts = []
        for p in self.project_ids:
            service_accounts.append(
                fake_service_accounts.FAKE_PROJECT_SERVICE_ACCOUNTS_MAP[p])

        print "aaaaaaaaaaaaa"
        print service_accounts
        service_account_keys = []
        for s in service_accounts:
            service_account_keys.append(
                fake_service_accounts.FAKE_SERVICE_ACCOUNT_KEYS[s[0]['name']])

        self.pipeline.api_client.get_service_accounts = mock.MagicMock(
            side_effect=service_accounts)
        self.pipeline.api_client.get_service_account_keys = mock.MagicMock(
            side_effect=service_account_keys)

        actual = self.pipeline._retrieve()

        self.assertEquals(
            fake_service_accounts.FAKE_PROJECT_SERVICE_ACCOUNTS_MAP,
            actual)

    @mock.patch.object(
        load_service_accounts_pipeline.LoadServiceAccountsPipeline,
        '_get_loaded_count')
    @mock.patch.object(
        load_service_accounts_pipeline.LoadServiceAccountsPipeline,
        '_load')
    @mock.patch.object(
        load_service_accounts_pipeline.LoadServiceAccountsPipeline,
        '_transform')
    @mock.patch.object(
        load_service_accounts_pipeline.LoadServiceAccountsPipeline,
        '_retrieve')
    def test_subroutines_are_called_by_run(
            self,
            mock_retrieve,
            mock_transform,
            mock_load,
            mock_get_loaded_count):
        """Test that the subroutines are called by run."""
        mock_retrieve.return_value = (
            fake_service_accounts.FAKE_PROJECT_SERVICE_ACCOUNTS_MAP)
        mock_transform.return_value = (
            fake_service_accounts.EXPECTED_LOADABLE_SERVICE_ACCOUNTS)
        self.pipeline.run()

        mock_transform.assert_called_once_with(
            fake_service_accounts.FAKE_PROJECT_SERVICE_ACCOUNTS_MAP)

        self.assertEquals(1, mock_load.call_count)

        # The regular data is loaded.
        called_args, called_kwargs = mock_load.call_args_list[0]
        expected_args = (
            self.pipeline.RESOURCE_NAME,
            fake_service_accounts.EXPECTED_LOADABLE_SERVICE_ACCOUNTS)
        self.assertEquals(expected_args, called_args)


if __name__ == '__main__':
      unittest.main()
