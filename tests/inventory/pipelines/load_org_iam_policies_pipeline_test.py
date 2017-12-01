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

"""Tests the load_org_iam_policies_pipeline."""

from tests.unittest_utils import ForsetiTestCase
import mock
import MySQLdb
import unittest

# pylint: disable=line-too-long
from google.cloud.forseti.common.data_access import errors as data_access_errors
from google.cloud.forseti.common.data_access import organization_dao as org_dao
from google.cloud.forseti.common.gcp_api import cloud_resource_manager as crm
from google.cloud.forseti.common.gcp_api import errors as api_errors
from google.cloud.forseti.common.gcp_type import organization
from google.cloud.forseti.inventory import errors as inventory_errors
from google.cloud.forseti.inventory.pipelines import load_org_iam_policies_pipeline
from tests.inventory.pipelines.test_data import fake_configs
from tests.inventory.pipelines.test_data import fake_iam_policies
# pylint: enable=line-too-long


class LoadOrgIamPoliciesPipelineTest(ForsetiTestCase):
    """Tests for the load_org_iam_policies_pipeline."""

    def setUp(self):
        """Set up."""
        self.cycle_timestamp = '20001225T120000Z'
        self.global_configs = fake_configs.FAKE_CONFIGS
        self.mock_crm = mock.create_autospec(crm.CloudResourceManagerClient)
        self.mock_dao = mock.create_autospec(org_dao.OrganizationDao)
        self.fake_id = '666666'
        self.pipeline = (
            load_org_iam_policies_pipeline.LoadOrgIamPoliciesPipeline(
                self.cycle_timestamp,
                self.global_configs,
                self.mock_crm,
                self.mock_dao))


    def test_can_transform_org_iam_policies(self):
        """Test that org iam policies can be transformed."""

        loadable_iam_policies = self.pipeline._transform(
            fake_iam_policies.FAKE_ORG_IAM_POLICY_MAP)
        self.assertEquals(fake_iam_policies.EXPECTED_LOADABLE_ORG_IAM_POLICY,
                          list(loadable_iam_policies))

    @unittest.skip("Pipelines will be removed in a future PR.")
    def test_api_is_called_to_retrieve_org_policies(self):
        """Test that api is called to retrieve org policies."""

        self.mock_dao.get_organizations.return_value = [
            organization.Organization(
                self.fake_id)]

        self.pipeline._retrieve()

        self.pipeline.api_client.get_org_iam_policies.assert_called_once_with(
            self.pipeline.RESOURCE_NAME,
            self.fake_id)

    def test_retrieve_error_raised_when_db_error(self):
        """Test that LoadDataPipelineError is raised when database error."""
        self.mock_dao.get_organizations.side_effect = (
            data_access_errors.MySQLError(
                'organizations', mock.MagicMock()))

        with self.assertRaises(inventory_errors.LoadDataPipelineError):
            self.pipeline._retrieve()

    @unittest.skip("Pipelines will be removed in a future PR.")
    @mock.patch(
        'google.cloud.forseti.inventory.pipelines.base_pipeline.LOGGER')
    def test_retrieve_error_logged_when_api_error(self, mock_logger):
        """Test that LOGGER.error() is called when there is an API error."""
        self.mock_dao.get_organizations.return_value = [
            organization.Organization(
                self.fake_id)]
        self.pipeline.api_client.get_org_iam_policies.side_effect = (
            api_errors.ApiExecutionError('11111', mock.MagicMock()))
        results = self.pipeline._retrieve()
        self.assertEqual([], results)
        self.assertEqual(1, mock_logger.error.call_count)

    @mock.patch.object(
        load_org_iam_policies_pipeline.LoadOrgIamPoliciesPipeline,
        '_get_loaded_count')
    @mock.patch.object(
        load_org_iam_policies_pipeline.LoadOrgIamPoliciesPipeline,
        '_load')
    @mock.patch.object(
        load_org_iam_policies_pipeline.LoadOrgIamPoliciesPipeline,
        '_transform')
    @mock.patch.object(
        load_org_iam_policies_pipeline.LoadOrgIamPoliciesPipeline,
        '_retrieve')
    def test_subroutines_are_called_by_run(self, mock_retrieve, mock_transform,
        mock_load, mock_get_loaded_count):
        """Test that the subroutines are called by run."""

        mock_retrieve.return_value = fake_iam_policies.FAKE_ORG_IAM_POLICY_MAP
        mock_transform.return_value = (
            fake_iam_policies.EXPECTED_LOADABLE_ORG_IAM_POLICY)
        self.pipeline.run()

        mock_transform.assert_called_once_with(
            fake_iam_policies.FAKE_ORG_IAM_POLICY_MAP)

        self.assertEquals(2, mock_load.call_count)

        # The regular data is loaded.
        called_args, called_kwargs = mock_load.call_args_list[0]
        expected_args = (
            self.pipeline.RESOURCE_NAME,
            fake_iam_policies.EXPECTED_LOADABLE_ORG_IAM_POLICY)
        self.assertEquals(expected_args, called_args)

        # The raw json data is loaded.
        called_args, called_kwargs = mock_load.call_args_list[1]
        expected_args = (
            self.pipeline.RAW_RESOURCE_NAME,
            fake_iam_policies.FAKE_ORG_IAM_POLICY_MAP)
        self.assertEquals(expected_args, called_args)

        mock_get_loaded_count.assert_called_once


if __name__ == '__main__':
      unittest.main()
