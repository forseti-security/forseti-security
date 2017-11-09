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

"""Tests the load_orgs_pipeline."""

from tests.unittest_utils import ForsetiTestCase
import json
import mock
import unittest

# pylint: disable=line-too-long
from google.cloud.forseti.common.data_access import errors as data_access_errors
from google.cloud.forseti.common.data_access import organization_dao as org_dao
from google.cloud.forseti.common.gcp_api import cloud_resource_manager as crm
from google.cloud.forseti.common.gcp_api import errors as api_errors
from google.cloud.forseti.inventory import errors as inventory_errors
from google.cloud.forseti.inventory.pipelines import load_orgs_pipeline
from tests.inventory.pipelines.test_data import fake_configs
from tests.inventory.pipelines.test_data import fake_orgs
# pylint: enable=line-too-long


def _setup_raw_orgs():
    for (i, o) in enumerate(fake_orgs.EXPECTED_LOADABLE_ORGS):
        fake_orgs.EXPECTED_LOADABLE_ORGS[i]['raw_org'] = json.dumps(
            fake_orgs.FAKE_ORGS[i])


class LoadOrgsPipelineTest(ForsetiTestCase):
    """Tests for the load_orgs_pipeline."""

    @classmethod
    def setUpClass(cls):
        """Set up before running the class tests."""
        _setup_raw_orgs()

    def setUp(self):
        """Set up."""
        self.cycle_timestamp = '20001225T120000Z'
        self.configs = fake_configs.FAKE_CONFIGS
        self.mock_crm = mock.create_autospec(crm.CloudResourceManagerClient)
        self.mock_dao = mock.create_autospec(org_dao.OrganizationDao)
        self.pipeline = (
            load_orgs_pipeline.LoadOrgsPipeline(
                self.cycle_timestamp,
                self.configs,
                self.mock_crm,
                self.mock_dao))

    def test_can_transform_orgs(self):
        """Test that orgs can be transformed."""

        orgs = list(self.pipeline._transform(fake_orgs.FAKE_ORGS))
        self.assertEquals(fake_orgs.EXPECTED_LOADABLE_ORGS, orgs)

    def test_api_is_called_to_retrieve_orgs(self):
        """Test that api is called to retrieve orgs."""

        self.pipeline._retrieve()

        self.pipeline.api_client.get_organizations.assert_called_once_with(
            self.pipeline.RESOURCE_NAME)

    @mock.patch(
        'google.cloud.forseti.inventory.pipelines.base_pipeline.LOGGER')
    def test_retrieve_errors_are_handled(self, mock_logger):
        """Test that errors are handled when retrieving."""

        self.pipeline.api_client.get_organizations.side_effect = (
            api_errors.ApiExecutionError('11111', mock.MagicMock()))

        results = self.pipeline._retrieve()
        self.assertEqual(None, results)
        self.assertEqual(1, mock_logger.error.call_count)

    @mock.patch.object(
        load_orgs_pipeline.LoadOrgsPipeline,
        '_get_loaded_count')
    @mock.patch.object(
        load_orgs_pipeline.LoadOrgsPipeline,
        '_load')
    @mock.patch.object(
        load_orgs_pipeline.LoadOrgsPipeline,
        '_transform')
    @mock.patch.object(
        load_orgs_pipeline.LoadOrgsPipeline,
        '_retrieve')
    def test_subroutines_are_called_by_run(self, mock_retrieve, mock_transform,
            mock_load, mock_get_loaded_count):
        """Test that the subroutines are called by run."""

        mock_retrieve.return_value = fake_orgs.FAKE_ORGS
        mock_transform.return_value = fake_orgs.EXPECTED_LOADABLE_ORGS
        self.pipeline.run()

        mock_retrieve.assert_called_once_with()

        mock_transform.assert_called_once_with(fake_orgs.FAKE_ORGS)

        mock_load.assert_called_once_with(
            self.pipeline.RESOURCE_NAME,
            fake_orgs.EXPECTED_LOADABLE_ORGS)

        mock_get_loaded_count.assert_called_once


if __name__ == '__main__':
      unittest.main()
