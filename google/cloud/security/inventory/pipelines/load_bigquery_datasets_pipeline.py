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

from google.cloud.security.common.gcp_api import errors as api_errors
from google.cloud.security.common.util import log_util
from google.cloud.security.common.util import parser
from google.cloud.security.inventory import errors as inventory_errors
from google.cloud.security.inventory.pipelines import base_pipeline


LOGGER = log_util.get_logger(__name__)


class LoadBigqueryDatasetsPipeline(base_pipeline.BasePipeline):
    """Pipeline to load bigquery datasets data into Inventory."""

    RESOURCE_NAME = 'bigquery_datasets'

    MYSQL_DATETIME_FORMAT = '%Y-%m-%d %H:%M:%S'

    def _retrieve_bigquery_projectids(self):
        """Retrieve a list of bigquery projectids.

        Returns:
            list: Project ids.

        Raises:
            inventory_errors.LoadDataPipelineError when we encounter an
                error in the underlying bigquery API.
        """
        try:
            return self.api_client.get_bigquery_projectids()
        except api_errors.ApiExecutionError as e:
            raise inventory_errors.LoadDataPipelineError(e)

    def _retrieve_dataset_access(self, project_id, dataset_id):
        """Retrieve the bigquery dataset resources from GCP.

        Args:
            project_id (str): A project id.
            dataset_id (str): A dataset id.

        Returns:
            list: Access lists for a given project_id and dataset_id.
                [{'role': 'WRITER', 'specialGroup': 'projectWriters'},
                 {'role': 'OWNER', 'specialGroup': 'projectOwners'},
                 {'role': 'OWNER', 'userByEmail': 'user@domain.com'},
                 {'role': 'READER', 'specialGroup': 'projectReaders'}]

        Raises:
            inventory_errors.LoadDataPipelineError when we encounter an
                error in the underlying bigquery API.
        """
        try:
            return self.api_client.get_dataset_access(project_id, dataset_id)
        except api_errors.ApiExecutionError as e:
            raise inventory_errors.LoadDataPipelineError(e)

    def _retrieve_dataset_project_map(self, project_ids):
        """Retrieve the bigquery datasets for all requested project ids.

        Args:
            project_ids (list): Project ids.

        Returns:
            list: A list of objects like:
                [[{'datasetId': 'test', 'projectId': 'bq-test'},
                 {'datasetId': 'test', 'projectId': 'bq-test'}],
                [{'datasetId': 'test', 'projectId': 'bq-test'},
                 {'datasetId': 'test', 'projectId': 'bq-test'}]]

        Raises:
            inventory_errors.LoadDataPipelineError when we encounter an
                error in the underlying bigquery API.
        """
        dataset_project_map = []
        for project_id in project_ids:
            try:
                result = self.api_client.get_datasets_for_projectid(project_id)
            except api_errors.ApiExecutionError as e:
                raise inventory_errors.LoadDataPipelineError(e)

            if result:
                dataset_project_map.append(result)

        return dataset_project_map

    def _retrieve_dataset_access_map(self, dataset_project_map):
        """Iteriate through projects and their datasets to get ACLs.

        Args:
            dataset_project_map (list): A list of projects and their datasets.
                See the output of _retrieve_dataset_project_map().

        Returns:
            list: A list of tuples in the form of:
                [(project_id,
                  dataset_id,
                  {dataset_access_object}),
                ...]
        """
        dataset_project_access_map = []
        for map_item in dataset_project_map:
            for item in map_item:
                project_id = item.get('projectId')
                dataset_id = item.get('datasetId')
                dataset_acl = self._retrieve_dataset_access(project_id,
                                                            dataset_id)

                if dataset_acl:
                    dataset_project_access_map.append(
                        (project_id, dataset_id, dataset_acl)
                        )

        return dataset_project_access_map

    def _transform(self, resource_from_api):
        """Yield an iterator of loadable groups.

        Args:
            resource_from_api (list): A list of tuples in the form of:
                [(project_id, dataset_id, {dataset_access_object}),...]

        Yields:
            iterable: An iterable of project_id, dataset_id, and access detail.
        """
        for (project_id, dataset_id, access) in resource_from_api:
            for acl in access:
                yield {
                    'project_id': project_id,
                    'dataset_id': dataset_id,
                    'access_domain': acl.get('domain'),
                    'access_user_by_email': acl.get('userByEmail'),
                    'access_special_group': acl.get('specialGroup'),
                    'access_group_by_email': acl.get('groupByEmail'),
                    'role': acl.get('role'),
                    'access_view_project_id': acl.get(
                        'view', {}).get('projectId'),
                    'access_view_table_id': acl.get(
                        'view', {}).get('tableId'),
                    'access_view_dataset_id': acl.get(
                        'view', {}).get('datasetId'),
                    'raw_access_map': parser.json_stringify(acl)
                }

    def _retrieve(self):
        """Retrieve dataset access lists.

        Returns:
            bigquery_dataset: A bigquery dataset access map.
                See _retrieve_dataset_access_map() or
                None if there are no bigquery projects.
        """
        project_ids = self._retrieve_bigquery_projectids()

        if not project_ids:
            LOGGER.info('No bigquery project ids found.')
            return None

        dataset_project_map = self._retrieve_dataset_project_map(project_ids)

        return self._retrieve_dataset_access_map(dataset_project_map)

    def run(self):
        """Runs the actual data fetching pipeline."""
        dataset_project_access_map = self._retrieve()

        if dataset_project_access_map is not None:
            loadable_datasets = self._transform(dataset_project_access_map)
            self._load(self.RESOURCE_NAME, loadable_datasets)
            self._get_loaded_count()
