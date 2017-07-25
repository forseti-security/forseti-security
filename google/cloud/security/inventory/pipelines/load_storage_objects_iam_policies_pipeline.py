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


class LoadStorageObjectsIamPoliciesPipeline(base_pipeline.BasePipeline):
    """Pipeline to load project bucket's objects data into Inventory."""

    RESOURCE_NAME = 'storage_object_iam_policies'
    RAW_RESOURCE_NAME = 'raw'

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

    def _iter_objects(self):
        """Return generator for GCS objects.

        Raises:
            LoadDataPipelineError: If the objects cannot be loaded.

        Yields:
            dict: GCS object.
        """
        try:
            for storage_object in (
                self.dao.get_objects(self.RESOURCE_NAME,
                                     self.cycle_timestamp)):
                yield storage_object
        except data_access_errors.MySQLError as e:
            raise inventory_errors.LoadDataPipelineError(e)

    def _iter_object_policies(self):
        """Return generator for GCS object IAM policies.

        Yields:
            dict: GCS object IAM policy.
        """
        for object_row in self._iter_objects():
            policy = self.api_client.get_object_iam_policy(
                object_row['bucket_id'],
                object_row['object_name'])

            yield {
                    'project_number': object_row['project_number'],
                    'bucket_id': object_row['bucket_id'],
                    'object_name': object_row['object_name'],
                    'raw': json.dumps(policy),
                }

    def run(self, progress_report=None):
        """Runs the load storage objects data pipeline."""

        self._load(self.RESOURCE_NAME, self._iter_object_policies())
