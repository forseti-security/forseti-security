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

"""Pipeline to load bucket acls into Inventory."""

import json

# pylint: disable=line-too-long
from google.cloud.security.common.data_access import errors as data_access_errors
from google.cloud.security.common.gcp_api import errors as api_errors
from google.cloud.security.common.util import log_util
from google.cloud.security.inventory import errors as inventory_errors
from google.cloud.security.inventory.pipelines import base_pipeline
# pylint: enable=line-too-long


LOGGER = log_util.get_logger(__name__)


class LoadProjectsBucketsAclsPipeline(base_pipeline.BasePipeline):
    """Pipeline to load project buckets data into Inventory."""

    PROJECTS_RESOURCE_NAME = 'project_iam_policies'
    RESOURCE_NAME = 'buckets_acl'

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
        super(LoadProjectsBucketsAclsPipeline, self).__init__(
            cycle_timestamp, configs, gcs_client, dao)

    def _transform(self, buckets_acls_maps):
        """Yield an iterator of loadable bucket acls.

        Args:
            buckets_acls_maps: An iterable of bucket acls as per-bucket
                dictionary.
                Example: {'bucket_name': 'axample_bucket_name.appspot.com',
                          'acl': bucket_acls_json}

        Yields:
            An iterable of bucket acls, as a per-bucket dictionary.
        """
        for buckets_map_acls in buckets_acls_maps:
            acls = buckets_map_acls['acl']
            acls_items = acls.get('items', [])

            for acl_item in acls_items:
                bucket_acl_json = json.dumps(acl_item)

                yield {
                    'bucket': buckets_map_acls['bucket_name'],
                    'domain': acl_item.get('domain'),
                    'email': acl_item.get('email'),
                    'entity': acl_item.get('entity'),
                    'entity_id': acl_item.get('entityId'),
                    'acl_id': acl_item.get('id'),
                    'kind': acl_item.get('kind'),
                    'project_team': json.dumps(acl_item.get('projectTeam', [])),
                    'role': acl_item.get('role'),
                    'bucket_acl_selflink': acl_item.get('selfLink'),
                    'raw_bucket_acl': bucket_acl_json
                    }

    def _retrieve(self):
        """Retrieve the project buckets acls from GCP.

        Args:
            None

        Returns:
            buckets_acl_maps: List of bucket acls as per-bucket dictionary.
                Example: [{bucket_name: 'bucket name',
                          acl: bucket_acls_json}]

        Raises:
            LoadDataPipelineException: An error with loading data has occurred.
        """
        # Get the projects for which we will retrieve the buckets.
        try:
            project_numbers = self.dao.get_project_numbers(
                self.PROJECTS_RESOURCE_NAME, self.cycle_timestamp)
        except data_access_errors.MySQLError as e:
            raise inventory_errors.LoadDataPipelineError(e)
        # Get the buckets for project numbers
        projects_buckets_maps = []
        for project_number in project_numbers:
            try:
                buckets = self.dao.get_buckets_by_project_number(
                    self.RESOURCE_NAME, self.cycle_timestamp,
                    project_number)
                project_buckets_map = {'project_number': project_number,
                                       'buckets': buckets}
                projects_buckets_maps.append(project_buckets_map)
            except data_access_errors.MySQLError as e:
                raise inventory_errors.LoadDataPipelineError(e)
        # Retrieve bucket acl data from GCP.
        buckets_acl_maps = []
        for project_buckets in projects_buckets_maps:
            buckets = project_buckets['buckets']
            for bucket in buckets:
                try:
                    bucket_acl = self.api_client.get_bucket_acls(
                        bucket)
                    bucket_acl_map = {'bucket_name': bucket,
                                      'acl': bucket_acl}
                    buckets_acl_maps.append(bucket_acl_map)
                except api_errors.ApiExecutionError as e:
                    LOGGER.error(
                        'Unable to get buckets acls for bucket %s:\n%s',
                        bucket, e)
        return buckets_acl_maps

    def run(self):
        """Runs the load buckets data pipeline."""
        buckets_acls_maps = self._retrieve()

        loadable_buckets_acls = self._transform(buckets_acls_maps)

        self._load(self.RESOURCE_NAME, loadable_buckets_acls)

        self._get_loaded_count()
