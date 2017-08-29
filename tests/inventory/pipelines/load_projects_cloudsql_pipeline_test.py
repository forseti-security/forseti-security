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

"""Tests the load_projects_cloudsql_pipeline."""

import mock
import unittest

# pylint: disable=line-too-long
from tests.unittest_utils import ForsetiTestCase
from google.cloud.security.common.data_access import errors as data_access_errors
from google.cloud.security.common.data_access import project_dao as proj_dao
from google.cloud.security.common.gcp_api import errors as api_errors
from google.cloud.security.common.gcp_api import cloudsql
from google.cloud.security.common.util import log_util
from google.cloud.security.inventory import errors as inventory_errors
from google.cloud.security.inventory.pipelines import \
     load_projects_cloudsql_pipeline
from tests.inventory.pipelines.test_data import fake_cloudsql
from tests.inventory.pipelines.test_data import fake_configs

from pprint import pprint


# pylint: enable=line-too-long
class LoadProjectsCloudsqlPipelineTest(ForsetiTestCase):
    """Tests for the load_projects_cloudsql_pipeline."""

    FAKE_PROJECT_NUMBERS = ['11111']

    def setUp(self):
        """Set up."""
        self.cycle_timestamp = '20001225T120000Z'
        self.configs = fake_configs.FAKE_CONFIGS
        self.mock_cloudsql = mock.create_autospec(cloudsql.CloudsqlClient)
        self.mock_dao = mock.create_autospec(proj_dao.ProjectDao)
        self.pipeline = (
            load_projects_cloudsql_pipeline.LoadProjectsCloudsqlPipeline(
                self.cycle_timestamp,
                self.configs,
                self.mock_cloudsql,
                self.mock_dao))

    def test_can_transform_cloudsql(self):
        """Test that cloudsql instances can be tranformed."""
        self.maxDiff = None
        loadable_cloudsql = dict()

        for resource, data_map in self.pipeline._transform(\
                fake_cloudsql.FAKE_CLOUDSQL_MAP).iteritems():
           loadable_cloudsql[resource] = list(data_map)

        actual_loaded_instances = loadable_cloudsql.values()[2]
        actual_loaded_ipaddresses = loadable_cloudsql.values()[1]
        actual_authorizednetworks = loadable_cloudsql.values()[0]

        self.assertEquals(
            fake_cloudsql.EXPECTED_LOADED_INSTANCES,
            actual_loaded_instances)
        self.assertEquals(
            fake_cloudsql.EXPECTED_LOADED_IPADDRESSES,
            actual_loaded_ipaddresses)
        self.assertEquals(
             fake_cloudsql.EXPECTED_LOADED_AUTHORIZEDNETWORKS,
             actual_authorizednetworks)

    def test_api_is_called_to_retrieve_cloudsql(self):
        """Test that api is called to retrive cloudsql instances."""

        self.pipeline.dao.get_project_numbers.return_value = (
            self.FAKE_PROJECT_NUMBERS)
        self.pipeline._retrieve()

        self.pipeline.dao.get_project_numbers.assert_called_once_with(
            self.pipeline.PROJECTS_RESOURCE_NAME,
            self.pipeline.cycle_timestamp)

        self.pipeline.api_client.get_instances.assert_called_once_with(
            self.FAKE_PROJECT_NUMBERS[0])

        self.assertEquals(
            1, self.pipeline.api_client.get_instances.call_count)

    @mock.patch(
        'google.cloud.security.inventory.pipelines.base_pipeline.LOGGER')
    def test_api_error_is_handled_when_retrieving(self, mock_logger):
        """Test that exceptions are handled when retrieving.

        We don't want to fail the pipeline when any one project's cloudsql
        instances can not be retrieved.  We just want to log the error,
        and continue with the other projects.
        """
        self.pipeline.dao.get_project_numbers.return_value = (
            self.FAKE_PROJECT_NUMBERS)
        self.pipeline.api_client.get_instances.side_effect = (
            api_errors.ApiExecutionError('error error', mock.MagicMock()))

        results = self.pipeline._retrieve()
        self.assertEqual([], results)
        self.assertEqual(1, mock_logger.error.call_count)

    @mock.patch.object(
        load_projects_cloudsql_pipeline.LoadProjectsCloudsqlPipeline,
        '_get_loaded_count')
    @mock.patch.object(
        load_projects_cloudsql_pipeline.LoadProjectsCloudsqlPipeline,
        '_load')
    @mock.patch.object(
        load_projects_cloudsql_pipeline.LoadProjectsCloudsqlPipeline,
        '_transform')
    @mock.patch.object(
        load_projects_cloudsql_pipeline.LoadProjectsCloudsqlPipeline,
        '_retrieve')
    def test_subroutines_are_called_by_run(self, mock_retrieve, mock_transform,
        mock_load, mock_get_loaded_count):
        """Test that the subroutines are called by run."""
        mock_retrieve.return_value = (
            fake_cloudsql.FAKE_CLOUDSQL_MAP)
        mock_transform.return_value = ({
            self.pipeline.RESOURCE_NAME_INSTANCES:
                fake_cloudsql.EXPECTED_LOADED_INSTANCES,
            self.pipeline.RESOURCE_NAME_IPADDRESSES:
                fake_cloudsql.EXPECTED_LOADED_IPADDRESSES,
            self.pipeline.RESOURCE_NAME_AUTHORIZEDNETWORKS:
                fake_cloudsql.EXPECTED_LOADED_AUTHORIZEDNETWORKS
        })
        self.pipeline.run()

        mock_retrieve.assert_called_once_with()

        mock_transform.assert_called_once_with(
            fake_cloudsql.FAKE_CLOUDSQL_MAP)

        self.assertEquals(3, mock_load.call_count)

        subtransform_calls = set()
        expected_subtransform_calls = set([
            self.pipeline.RESOURCE_NAME_IPADDRESSES,
            self.pipeline.RESOURCE_NAME_INSTANCES,
            self.pipeline.RESOURCE_NAME_AUTHORIZEDNETWORKS])


        for load_call_args in mock_load.call_args_list:

            called_args, called_kwargs = load_call_args

            # The regular data is loaded.
            if called_args[0] == self.pipeline.RESOURCE_NAME_INSTANCES:
                expected_args = (
                    self.pipeline.RESOURCE_NAME_INSTANCES,
                    fake_cloudsql.EXPECTED_LOADED_INSTANCES)
                subtransform_calls.add(self.pipeline.RESOURCE_NAME_INSTANCES)
            # The ip addresses are loaded
            elif called_args[0] == self.pipeline.RESOURCE_NAME_IPADDRESSES:
                expected_args = (
                    self.pipeline.RESOURCE_NAME_IPADDRESSES,
                    fake_cloudsql.EXPECTED_LOADED_IPADDRESSES)
                subtransform_calls.add(self.pipeline.RESOURCE_NAME_IPADDRESSES)
            # The authorized networks are loaded.
            elif called_args[0] == self.\
                pipeline.RESOURCE_NAME_AUTHORIZEDNETWORKS:
                expected_args = (
                    self.pipeline.RESOURCE_NAME_AUTHORIZEDNETWORKS,
                    fake_cloudsql.EXPECTED_LOADED_AUTHORIZEDNETWORKS)
                subtransform_calls.add(self.\
                        pipeline.RESOURCE_NAME_AUTHORIZEDNETWORKS)

            self.assertEquals(expected_args, called_args)

        self.assertEquals(expected_subtransform_calls, subtransform_calls)

        mock_get_loaded_count.assert_called_once


if __name__ == '__main__':
    unittest.main()
