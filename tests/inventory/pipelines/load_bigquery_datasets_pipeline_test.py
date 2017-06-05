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

"""Tests the load_bigquery_datasets_pipeline."""


from tests.unittest_utils import ForsetiTestCase
import mock

# pylint: disable=line-too-long
from google.cloud.security.common.data_access import project_dao
from google.cloud.security.common.gcp_api import bigquery as bq
from google.cloud.security.common.gcp_api import errors as api_errors
from google.cloud.security.inventory import errors as inventory_errors
from google.cloud.security.inventory.pipelines import load_bigquery_datasets_pipeline
from tests.inventory.pipelines.test_data import fake_bigquery_datasets as fbq
from tests.inventory.pipelines.test_data import fake_configs
# pylint: enable=line-too-long


class LoadBigqueryDatasetsPipelineTest(ForsetiTestCase):
    """Tests for the load_bigquery_datasets_pipeline."""

    def setUp(self):
        """Set up."""

        self.RESOURCE_NAME = 'bigquery'
        self.cycle_timestamp = '20001225T120000Z'
        self.configs = fake_configs.FAKE_CONFIGS
        self.mock_bigquery_client = mock.create_autospec(bq.BigQueryClient)
        self.mock_dao = mock.create_autospec(project_dao.ProjectDao)
        self.pipeline = (
            load_bigquery_datasets_pipeline.LoadBigqueryDatasetsPipeline(
                self.cycle_timestamp,
                self.configs,
                self.mock_bigquery_client,
                self.mock_dao))

    def test_retrieve_bigquery_projectids_raises(self):
        self.pipeline.api_client.get_bigquery_projectids.side_effect = (
            api_errors.ApiExecutionError('', mock.MagicMock()))

        with self.assertRaises(inventory_errors.LoadDataPipelineError):
            self.pipeline._retrieve_bigquery_projectids()

    def test_retrieve_bigquery_projectids(self):
        self.pipeline.api_client.get_bigquery_projectids.return_value = (
            fbq.GET_PROJECTIDS_RETURN
        )

        return_value = self.pipeline._retrieve_bigquery_projectids()

        self.assertListEqual(
            fbq.EXPECTED_PROJECTIDS,
            return_value)

    def test_retrieve_dataset_project_map_raises(self):
        self.pipeline.api_client.get_datasets_for_projectid.side_effect = (
            api_errors.ApiExecutionError('', mock.MagicMock()))

        with self.assertRaises(inventory_errors.LoadDataPipelineError):
            self.pipeline._retrieve_dataset_project_map(['1', '2'])

    def test_retrieve_dataset_project_map(self):
        self.pipeline.api_client.get_datasets_for_projectid.side_effect = [
            fbq.GET_DATASETS_FOR_PROJECTIDS_RETURN,
            fbq.GET_DATASETS_FOR_PROJECTIDS_RETURN
        ]

        return_value = self.pipeline._retrieve_dataset_project_map(['1', '2'])

        self.assertListEqual(
            fbq.RETRIEVE_DATASET_PROJECT_MAP_EXPECTED,
            return_value)

    def test_retrieve_dataset_access_raises(self):
        self.pipeline.api_client.get_dataset_access.side_effect = (
            api_errors.ApiExecutionError('', mock.MagicMock())
        )

        with self.assertRaises(inventory_errors.LoadDataPipelineError):
            self.pipeline._retrieve_dataset_access('1', '2')

    def test_retrieve_dataset_access(self):
        self.pipeline.api_client.get_dataset_access.return_value = (
            fbq.GET_DATASET_ACCESS_RETURN
        )

        return_value = self.pipeline._retrieve_dataset_access('1', '2')

        self.assertListEqual(fbq.RETRIEVE_DATASET_ACCESS_RETURN, return_value)

    def test_retrieve_dataset_project_map_raises(self):
        self.pipeline.api_client.get_datasets_for_projectid.side_effect = (
            api_errors.ApiExecutionError('', mock.MagicMock())
        )

        with self.assertRaises(inventory_errors.LoadDataPipelineError):
            self.pipeline._retrieve_dataset_project_map([''])

    def test_retrieve_dataset_project_map(self):
        self.pipeline.api_client.get_datasets_for_projectid.side_effect = (
            fbq.GET_DATASETS_FOR_PROJECTIDS_RETURN,
            fbq.GET_DATASETS_FOR_PROJECTIDS_RETURN
            )

        return_value = self.pipeline._retrieve_dataset_project_map(['1', '2'])

        self.assertListEqual(
            fbq.DATASET_PROJECT_MAP_EXPECTED,
            return_value)

    @mock.patch.object(
        load_bigquery_datasets_pipeline.LoadBigqueryDatasetsPipeline,
        '_retrieve_dataset_access' )
    def test_get_dataset_access_map(self, mock_dataset_access):
        mock_dataset_access.return_value = (
            fbq.RETRIEVE_DATASET_ACCESS_RETURN)

        return_value = self.pipeline._retrieve_dataset_access_map(
            fbq.DATASET_PROJECT_MAP)

        self.assertListEqual(fbq.DATASET_PROJECT_ACCESS_MAP_EXPECTED,
                             return_value)

    def test_transform(self):
        return_values = []

        for v in self.pipeline._transform(fbq.DATASET_PROJECT_ACCESS_MAP):
            return_values.append(v)

        self.assertListEqual(fbq.EXPECTED_TRANSFORM, return_values)

    def test_retrieve_with_no_bigquery_project_ids(self):
        self.pipeline.api_client = mock.MagicMock()
        self.pipeline.api_client.get_dataset_access = mock.MagicMock()
        self.pipeline.api_client.get_datasets_for_projectid = mock.MagicMock()
        self.pipeline._retrieve_dataset_project_map = mock.MagicMock()

        self.pipeline.api_client.get_bigquery_projectids.return_value = []

        return_value = self.pipeline._retrieve()

        self.assertEqual(None, return_value)
        self.pipeline.api_client.get_dataset_access.assert_not_called()
        self.pipeline.api_client.get_datasets_for_projectid.assert_not_called()
        self.pipeline._retrieve_dataset_project_map.assert_not_called()

    def test_retrieve(self):
        self.pipeline.api_client.get_bigquery_projectids.return_value = (
            fbq.GET_PROJECTIDS_RETURN
        )

        self.pipeline.api_client.get_datasets_for_projectid.side_effect = [
            fbq.GET_DATASETS_FOR_PROJECTIDS_RETURN,
            fbq.GET_DATASETS_FOR_PROJECTIDS_RETURN
        ]

        self.pipeline.api_client.get_dataset_access.return_value = (
            fbq.GET_DATASET_ACCESS_RETURN
        )

        return_value = self.pipeline._retrieve()

        self.assertListEqual(fbq.DATASET_PROJECT_ACCESS_MAP_EXPECTED,
                             return_value)


    @mock.patch.object(
        load_bigquery_datasets_pipeline.LoadBigqueryDatasetsPipeline,
        '_get_loaded_count')
    @mock.patch.object(
        load_bigquery_datasets_pipeline.LoadBigqueryDatasetsPipeline,
        '_load')
    @mock.patch.object(
        load_bigquery_datasets_pipeline.LoadBigqueryDatasetsPipeline,
        '_transform')
    @mock.patch.object(
        load_bigquery_datasets_pipeline.LoadBigqueryDatasetsPipeline,
        '_retrieve')
    def test_subroutines_are_called_by_run(self, mock_retrieve, mock_transform,
            mock_load, mock_get_loaded_count):
        """Test that the subroutines are called by run."""

        mock_retrieve.return_value = fbq.DATASET_PROJECT_MAP
        mock_transform.return_value = fbq.EXPECTED_TRANSFORM
        self.pipeline.run()

        mock_retrieve.assert_called_once_with()

        mock_transform.assert_called_once_with(fbq.DATASET_PROJECT_MAP)

        mock_load.assert_called_once_with(
            self.pipeline.RESOURCE_NAME,
            fbq.EXPECTED_TRANSFORM)

        mock_get_loaded_count.assert_called_once()
