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

"""Pipeline to load storage objects data into Inventory."""

import json

from dateutil import parser as dateutil_parser

# pylint: disable=line-too-long
from google.cloud.security.common.data_access import errors as data_access_errors
from google.cloud.security.common.util import log_util
from google.cloud.security.inventory import errors as inventory_errors
from google.cloud.security.inventory.pipelines import base_pipeline
# pylint: enable=line-too-long


LOGGER = log_util.get_logger(__name__)


class LoadStorageBucketsIamPoliciesPipeline(base_pipeline.BasePipeline):
    """Pipeline to load project bucket's objects data into Inventory."""

    RESOURCE_NAME = 'raw_bucket_iam_policies'
    RAW_RESOURCE_NAME = 'raw'
    PROJECTS_RESOURCE_NAME = 'project_iam_policies'
    BUCKETS_RESOURCE_NAME = 'buckets'

    def _transform(self):
        """Not Implemented.

        Args:
            resource_from_api (dict): Resources from API responses.
        Raises:
            NotImplementedError: Because not implemented.
        """

        raise NotImplementedError()

    def _retrieve(self):
        """Not Implemented.

        Raises:
            NotImplementedError: Because not implemented.
        """

        raise NotImplementedError()

    def _iter_projects(self):
        """Retrieve the projects from the database."""

        try:
            project_numbers = self.dao.get_project_numbers(
                self.PROJECTS_RESOURCE_NAME, self.cycle_timestamp)
            for project_number in project_numbers:
                yield project_number
        except data_access_errors.MySQLError as e:
            raise inventory_errors.LoadDataPipelineError(e)

    def _iter_buckets(self, project_number):
        """Retrieve the buckets by project from the database."""

        try:
            buckets = self.dao.get_buckets_by_project_number(
                self.BUCKETS_RESOURCE_NAME, self.cycle_timestamp,
                project_number)
            for bucket in buckets:
                yield bucket
        except data_access_errors.MySQLError as e:
            raise inventory_errors.LoadDataPipelineError(e)

    def _iter_bucket_policies(self):
        for project_number in self._iter_projects():
            for bucket in self._iter_buckets(project_number):
                policy = self.api_client.get_bucket_iam_policy(bucket)

                yield {
                    'project_number': project_number,
                    'bucket_id': bucket,
                    'raw': json.dumps(policy),
                    }

    def run(self, progress_report=None):
        """Runs the load storage objects data pipeline."""

        self._load(self.RESOURCE_NAME, self._iter_bucket_policies())
