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

"""Pipeline to load bigquery datasets data into Inventory."""

from MySQLdb import MySQLError

from google.cloud.security.common.gcp_api import errors as api_errors
from google.cloud.security.common.util import log_util
from google.cloud.security.inventory import errors as inventory_errors
from google.cloud.security.inventory.pipelines import base_pipeline
from google.cloud.security.common.data_access import project_dao

LOGGER = log_util.get_logger(__name__)


class LoadBigQueryDatasets(base_pipeline.BasePipeline):
    """Pipeline to load bigquery datasets data into Inventory."""

    RESOURCE_NAME = 'bigquery'

    MYSQL_DATETIME_FORMAT = '%Y-%m-%d %H:%M:%S'

    def _get_project_ids_from_dao(self):
        """Retrieve a list of project ids from the inventory.

        Returns: A list of project ids.

        Raises: inventory_errors.LoadDataPipelineError if MySQL errors are
        encountered
        """
        try:
            return project_dao.get_project_ids(self.api_client,
                                               self.cycle_timestamp)
        except MySQLError as e:
            LOGGER.error('Error fetching project ids from MySQL: %s', e)
            raise inventory_errors.LoadDataPipelineError

    def _get_dataset_by_projectid(self, project_id):
        """Retrieve the bigquery dataset resources from GCP.

        Args:
            project_id: A project id.

        Returns:
            None or a list of objects like:
            [{'projectId': 'string', 'datasetId': 'string'},
             {'projectId': 'string', 'datasetId': 'string'},
             {'projectId': 'string', 'datasetId': 'string'}]
        """
        return self.api_client.get_datasets_for_project_id(project_id)

    def _get_dataset_access(self, project_id, dataset_id):
        """Retrieve the bigquery dataset resources from GCP.

        Args:
            project_id: A project id.
            dataset_id: A dataset id.

        Returns: See bigquery.get_dataset_access().
        """
        return self.api_client.get_dataset_access(project_id, dataset_id)

    def _get_dataset_project_map(self, project_ids):
        """Retrieve the bigquery datasets for all requested project ids.

        Args:
            project_ids: A list of project ids.

        Returns:
            A list of objects like:
            [{'projectId': 'string', 'datasetId': 'string'},
             {'projectId': 'string', 'datasetId': 'string'},
             {'projectId': 'string', 'datasetId': 'string'}]
        """
        dataset_by_project_map = []
        for project_id in project_ids:
            datasets = self.retrieve_dataset_by_projectid(project_id)
            dataset_by_project_map.append(datasets)

        return dataset_by_project_map

    def _get_dataset_access_map(self, dataset_project_map):
        """Iteriate through projects and their datasets to get ACLs.

        Args:
            dataset_project_map: A list of projects and their datasets.
            See the output of _get_dataset_project_map().

        Returns:
            A list of tuples in the form of:
            [(project_id, dataset_id, {dataset_access_object}),...]
        """
        dataset_project_access_map = []
        for dataset_project in dataset_project_map:
            project_id = dataset_project.get('projectId')
            dataset_id = dataset_project.get('datasetId')
            dataset_acl = self._get_dataset_access(project_id, dataset_id)
            dataset_project_access_map.append(
                (project_id, dataset_id, dataset_acl)
            )

        return dataset_project_access_map

    def _transform(self, dataset_project_access_map):
        """Yield an iterator of loadable groups.

        Args:
            dataset_project_access_map:

            A list of tuples in the form of:
                [(project_id, dataset_id, {dataset_access_object}),...]

        Yields:
            An iterable of project_id, dataset_id, and access detail.
        """
        for (project_id, dataset_id, access_map) in dataset_project_access_map:
            for access in access_map:
                yield {'project_id': project_id,
                       'datset_id': dataset_id,
                       'access_domain': access.get('domain'),
                       'access_user_by_email': access.get('userByEmail'),
                       'access_special_group': access.get('specialGroup'),
                       'access_group_by_email': access.get('groupByEmail'),
                       'role': access.get('role'),
                       'access_view_project_id': access.get(
                           'view').get('projectId'),
                       'access_view_table_id': access.get(
                           'view').get('table_id'),
                       'access_view_dataset_id': access.get(
                           'view').get('datasetId')}


    def run(self):
        """Runs the data pipeline."""
        project_ids = self._get_project_ids_from_dao()

        dataset_project_map = self._get_dataset_project_map(project_ids)
        dataset_project_access_map = self._get_dataset_access_map(
            dataset_project_map)

        loadable_datasets = self._transform(dataset_project_access_map)

        self._load(self.RESOURCE_NAME, loadable_datasets)

        self._get_loaded_count()
