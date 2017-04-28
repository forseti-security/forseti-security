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

"""Pipeline to load project buckets data into Inventory."""

import json

from dateutil import parser as dateutil_parser

# pylint: disable=line-too-long
from google.cloud.security.common.data_access import errors as data_access_errors
from google.cloud.security.common.gcp_api import errors as api_errors
from google.cloud.security.common.util import log_util
from google.cloud.security.common.util import parser
from google.cloud.security.inventory import errors as inventory_errors
from google.cloud.security.inventory.pipelines import base_pipeline
# pylint: enable=line-too-long


LOGGER = log_util.get_logger(__name__)


class LoadProjectsBucketsPipeline(base_pipeline.BasePipeline):
    """Pipeline to load project buckets data into Inventory."""

    PROJECTS_RESOURCE_NAME = 'project_iam_policies'
    RESOURCE_NAME = 'buckets'
    RAW_RESOURCE_NAME = 'raw_buckets'

    MYSQL_DATETIME_FORMAT = '%Y-%m-%d %H:%M:%S'

    def __init__(self, cycle_timestamp, configs, gcs_client, dao):
        """Constructor for the data pipeline.

        Args:
            cycle_timestamp: String of timestamp, formatted as YYYYMMDDTHHMMSSZ.
            configs: Dictionary of configurations.
            gcs_client: GCS API client.
            dao: Data access object.

        Returns:
            None
        """
        super(LoadProjectsBucketsPipeline, self).__init__(
            cycle_timestamp, configs, gcs_client, dao)

    def _transform(self, buckets_maps):
        """Yield an iterator of loadable buckets.

        Args:
            buckets_maps: An iterable of buckets as per-project
                dictionary.
                Example: {'project_number': 11111,
                          'buckets': buckets_json}

        Yields:
            An iterable of buckets, as a per-org dictionary.
        """
        for buckets_map in buckets_maps:
            buckets = buckets_map['buckets']
            items = buckets.get('items', [])

            for item in items:
                bucket_json = json.dumps(item)

                try:
                    parsed_time = dateutil_parser.parse(item.get('timeCreated'))
                    formatted_project_create_time = (
                        parsed_time.strftime(self.MYSQL_DATETIME_FORMAT))
                except (TypeError, ValueError) as e:
                    LOGGER.error(
                        'Unable to parse timeCreated from bucket: %s\n%s',
                        item.get('timeCreated', ''), e)
                    formatted_project_create_time = '0000-00-00 00:00:00'

                try:
                    parsed_time = dateutil_parser.parse(item.get('updated'))
                    formatted_project_updated_time = (
                        parsed_time.strftime(self.MYSQL_DATETIME_FORMAT))
                except (TypeError, ValueError) as e:
                    LOGGER.error(
                        'Unable to parse updated from bucket: %s\n%s',
                        item.get('updated', ''), e)
                    formatted_project_updated_time = '0000-00-00 00:00:00'

                lifecycle = json.dumps(item.get('lifecycle', []))

                yield {
                    'project_number': buckets_map['project_number'],
                    'bucket_id': item.get('id'),
                    'bucket_name': item.get('name'),
                    'bucket_kind': item.get('kind'),
                    'bucket_storage_class': item.get('storageClass'),
                    'bucket_location': item.get('location'),
                    'bucket_create_time': formatted_project_create_time,
                    'bucket_update_time': formatted_project_updated_time,
                    'bucket_selflink': item.get('selfLink'),
                    'bucket_lifecycle_raw': lifecycle,
                    'raw_bucket': bucket_json}

    def _retrieve(self):
        """Retrieve the project buckets from GCP.

        Args:
            None

        Returns:
            buckets_maps: List of buckets as per-project dictionary.
                Example: [{project_number: project_number,
                          buckets: buckets_json}]

        Raises:
            LoadDataPipelineException: An error with loading data has occurred.
        """
        # Get the projects for which we will retrieve the buckets.
        try:
            project_numbers = self.dao.get_project_numbers(
                self.PROJECTS_RESOURCE_NAME, self.cycle_timestamp)
        except data_access_errors.MySQLError as e:
            raise inventory_errors.LoadDataPipelineError(e)
        # Retrieve data from GCP.
        buckets_maps = []
        for project_number in project_numbers:
            try:
                buckets = self.api_client.get_buckets(
                    project_number)
                buckets_map = {'project_number': project_number,
                               'buckets': buckets}
                buckets_maps.append(buckets_map)
            except api_errors.ApiExecutionError as e:
                LOGGER.error(
                    'Unable to get buckets for project %s:\n%s',
                    project_number, e)
        return buckets_maps

    def run(self):
        """Runs the load buckets data pipeline."""
        buckets_maps = self._retrieve()

        loadable_buckets = self._transform(buckets_maps)

        self._load(self.RESOURCE_NAME, loadable_buckets)

        # A separate table is used to store the raw buckets json
        # because it is much faster than updating these individually
        # into the projects table.

        for i in buckets_maps:
            i['buckets'] = json.dumps(i['buckets'])
        self._load(self.RAW_RESOURCE_NAME, buckets_maps)

        self._get_loaded_count()
