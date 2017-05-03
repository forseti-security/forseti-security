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

import json

from dateutil import parser as dateutil_parser
from MySQLdb import MySQLError

from google.cloud.security.common.gcp_api import errors as api_errors
from google.cloud.security.common.gcp_type.resource import LifecycleState
from google.cloud.security.common.util import log_util
from google.cloud.security.inventory import errors as inventory_errors
from google.cloud.security.inventory.pipelines import base_pipeline
from google.cloud.security.common.data_access.sql_queries import project_dao

LOGGER = log_util.get_logger(__name__)


class LoadBigQueryDatasets(base_pipeline.BasePipeline):
    """Pipeline to load bigquery datasets data into Inventory."""

    RESOURCE_NAME = 'bigquery'

    MYSQL_DATETIME_FORMAT = '%Y-%m-%d %H:%M:%S'

    def _retreive_datasets(self):
        datasets = self.api_client.get_datasets()
        return

    def _retrieve_project_ids_from_dao(self):
        try:
            return project_dao.get_project_ids()
        except MySQLError as e:
            LOGGER.error('Error fetching project ids from MySQL.')
            raise inventory_errors.LoadDataPipelineError

    def _retrieve(self):
        """Retrieve the bigquery dataset resources from GCP.
        """
        datasets_api_objects = self._retrieve_datasets()


    def run(self):
        """Runs the data pipeline."""
        projects_map = self._retrieve()

        loadable_projects = self._transform(projects_map)

        self._load(self.RESOURCE_NAME, loadable_projects)

        self._get_loaded_count()
