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

"""Pipeline to load bucket acls into Inventory."""

import json

# pylint: disable=line-too-long
from google.cloud.security.common.data_access import errors as data_access_errors
from google.cloud.security.common.util import log_util
from google.cloud.security.inventory import errors as inventory_errors
from google.cloud.security.inventory.pipelines import base_pipeline
# pylint: enable=line-too-long


LOGGER = log_util.get_logger(__name__)


class LoadProjectsBucketsAclsPipeline(base_pipeline.BasePipeline):
    """Pipeline to load project buckets data into Inventory."""

    PROJECTS_RESOURCE_NAME = 'project_iam_policies'
    RESOURCE_NAME = 'buckets_acl'

    def _transform(self, resource_from_api):
        """Yield an iterator of loadable bucket acls.

        Args:
            resource_from_api (iterable): Bucket acls as per-bucket
                dictionary.
                Example: {'bucket_name': 'example_bucket_name.appspot.com',
                          'acl': bucket_acls_json}

        Yields:
            iterable: bucket acls, as a per-bucket dictionary.
        """
        for buckets_acls_map in resource_from_api:
            acls = buckets_acls_map['acl']

            for acl_item in acls:
                bucket_acl_json = json.dumps(acl_item)

                yield {
                    'bucket': buckets_acls_map['bucket_name'],
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

        Returns:
            list: Bucket acls as per-bucket dictionary.
                Example: [{bucket_name: 'bucket name',
                          acl: bucket_acls_json}]

        Raises:
            LoadDataPipelineException: An error with loading data has occurred.
        """
        buckets_acls = []

        # Get the projects for which we will retrieve the buckets.
        try:
            raw_buckets = self.dao.get_raw_buckets(self.cycle_timestamp)
        except data_access_errors.MySQLError as e:
            raise inventory_errors.LoadDataPipelineError(e)

        for result in raw_buckets:
            try:
                raw_bucket_json = json.loads(result.get('raw_bucket'))
                bucket_acls = raw_bucket_json.get('acl')
            except ValueError as err:
                LOGGER.warn('Invalid json: %s', err)
                continue

            if bucket_acls:
                buckets_acls.append({
                    'bucket_name': result.get('bucket_id'),
                    'acl': bucket_acls
                })
        return buckets_acls

    def run(self):
        """Runs the load buckets data pipeline."""
        buckets_acls_maps = self._retrieve()

        loadable_buckets_acls = self._transform(buckets_acls_maps)

        self._load(self.RESOURCE_NAME, loadable_buckets_acls)

        self._get_loaded_count()
