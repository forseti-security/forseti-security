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

"""Tests the load_projects_buckets_pipeline."""

from tests.unittest_utils import ForsetiTestCase
import mock
import unittest

# pylint: disable=line-too-long
from google.cloud.security.common.data_access import errors as data_access_errors
from google.cloud.security.common.data_access import project_dao as proj_dao
from google.cloud.security.common.gcp_api import errors as api_errors
from google.cloud.security.common.gcp_api import storage
from google.cloud.security.common.util import log_util
from google.cloud.security.inventory import errors as inventory_errors
from google.cloud.security.inventory.pipelines import load_projects_buckets_pipeline
from tests.inventory.pipelines.test_data import fake_buckets
from tests.inventory.pipelines.test_data import fake_configs
# pylint: enable=line-too-long


class LoadProjectsBucketsPipelineTest(ForsetiTestCase):
    """Tests for the load_projects_buckets_pipeline."""

    FAKE_PROJECT_NUMBERS = ['11111']

    def setUp(self):
        """Set up."""

        self.cycle_timestamp = '20001225T120000Z'
        self.configs = fake_configs.FAKE_CONFIGS
        self.mock_gcs = mock.create_autospec(storage.StorageClient)
        self.mock_dao = mock.create_autospec(proj_dao.ProjectDao)
        self.pipeline = (
            load_projects_buckets_pipeline.LoadProjectsBucketsPipeline(
                self.cycle_timestamp,
                self.configs,
                self.mock_gcs,
                self.mock_dao))

    def test_can_transform_buckets(self):
        """Test that buckets can be tranformed."""

        loadable_buckets = list(self.pipeline._transform(
            fake_buckets.FAKE_BUCKETS_MAP))
        self.assertEquals(
            fake_buckets.EXPECTED_LOADABLE_BUCKETS,
            loadable_buckets)

    def test_api_is_called_to_retrieve_buckets(self):
        """Test that api is called to retrive buckets."""

        self.pipeline.dao.get_project_numbers.return_value = (
            self.FAKE_PROJECT_NUMBERS)
        self.pipeline._retrieve()

        self.pipeline.dao.get_project_numbers.assert_called_once_with(
            self.pipeline.PROJECTS_RESOURCE_NAME,
            self.pipeline.cycle_timestamp)

        self.pipeline.api_client.get_buckets.assert_called_once_with(
            self.FAKE_PROJECT_NUMBERS[0])

        self.assertEquals(
            1, self.pipeline.api_client.get_buckets.call_count)

    def test_api_error_is_handled_when_retrieving(self):
        """Test that exceptions are handled when retrieving.

        We don't want to fail the pipeline when any one project's buckets
    can not be retrieved.  We just want to log the error, and continue
    with the other projects.
        """
        load_projects_buckets_pipeline.LOGGER = (
            mock.create_autospec(log_util).get_logger('foo'))
        self.pipeline.dao.get_project_numbers.return_value = (
            self.FAKE_PROJECT_NUMBERS)
        self.pipeline.api_client.get_buckets.side_effect = (
            api_errors.ApiExecutionError('error error', mock.MagicMock()))

        self.pipeline._retrieve()

        self.assertEquals(
            1,
            load_projects_buckets_pipeline.LOGGER.error.call_count)

    @mock.patch.object(
        load_projects_buckets_pipeline.LoadProjectsBucketsPipeline,
        '_get_loaded_count')
    @mock.patch.object(
        load_projects_buckets_pipeline.LoadProjectsBucketsPipeline,
        '_load')
    @mock.patch.object(
        load_projects_buckets_pipeline.LoadProjectsBucketsPipeline,
        '_transform')
    @mock.patch.object(
        load_projects_buckets_pipeline.LoadProjectsBucketsPipeline,
        '_retrieve')
    def test_subroutines_are_called_by_run(self, mock_retrieve, mock_transform,mock_load, mock_get_loaded_count):
        """Test that the subroutines are called by run."""
        mock_retrieve.return_value = (
            fake_buckets.FAKE_BUCKETS_MAP)
        mock_transform.return_value = (
            fake_buckets.EXPECTED_LOADABLE_BUCKETS)
        self.pipeline.run()

        mock_retrieve.assert_called_once_with()

        mock_transform.assert_called_once_with(
            fake_buckets.FAKE_BUCKETS_MAP)

        self.assertEquals(2, mock_load.call_count)

        # The regular data is loaded.
        called_args, called_kwargs = mock_load.call_args_list[0]
        expected_args = (
            self.pipeline.RESOURCE_NAME,
            fake_buckets.EXPECTED_LOADABLE_BUCKETS)
        self.assertEquals(expected_args, called_args)

        # The raw json data is loaded.
        called_args, called_kwargs = mock_load.call_args_list[1]
        expected_args = (
            self.pipeline.RAW_RESOURCE_NAME,
            fake_buckets.FAKE_BUCKETS_MAP)
        self.assertEquals(expected_args, called_args)

        mock_get_loaded_count.assert_called_once


if __name__ == '__main__':
    unittest.main()
