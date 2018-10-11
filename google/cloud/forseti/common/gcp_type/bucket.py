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
"""A Bucket Resource.

See: https://cloud.google.com/storage/docs/json_api/v1/
"""

import json

from google.cloud.forseti.common.gcp_type import resource


class BucketLifecycleState(resource.LifecycleState):
    """Represents the Bucket's LifecycleState."""
    pass


class Bucket(resource.Resource):
    """Bucket resource."""

    RESOURCE_NAME_FMT = 'buckets/%s'

    def __init__(
            self,
            bucket_id,
            full_name=None,
            data=None,
            name=None,
            display_name=None,
            parent=None,
            lifecycle_state=BucketLifecycleState.UNSPECIFIED,
            retentions=None):
        """Initialize.

        Args:
            bucket_id (int): The bucket id.
            full_name (str): The full resource name and ancestry.
            data (str): Resource representation of the bucket.
            name (str): The bucket's unique GCP name, with the
                format "buckets/{id}".
            display_name (str): The bucket's display name.
            parent (Resource): The parent Resource.
            lifecycle_state (LifecycleState): The lifecycle state of the
                bucket.
            retentions (list): A list of RetentionInfo
        """
        super(Bucket, self).__init__(
            resource_id=bucket_id,
            resource_type=resource.ResourceType.BUCKET,
            name=name,
            display_name=display_name,
            parent=parent,
            lifecycle_state=lifecycle_state,
            retentions=retentions)
        self.full_name = full_name
        self.data = data

    @classmethod
    def from_json(cls, parent, json_string):
        """Create a bucket from a JSON string.
        Args:
            parent (Resource): resource this bucket belongs to.
            json_string(str): JSON string of a bucket GCP API response.
        Returns:
            Bucket: bucket resource.
        """
        bucket_dict = json.loads(json_string)
        bucket_id = bucket_dict['id']
        return cls(
            parent=parent,
            bucket_id=bucket_id,
            name='buckets/' + bucket_id,
            full_name='{}bucket/{}/'.format(parent.full_name, bucket_id),
            display_name=bucket_id,
            # locations=[bucket_dict['location']],
            retentions=Bucket.get_retentions_list_from_json(bucket_dict),
            data=json_string,
        )

    @classmethod
    def get_retentions_list_from_json(cls, bucket_dict):
        """Get the retention of the bucket from a dict.
        Args:
            bucket_dict(dict): The dict contains what is decoded from JSON

        Returns:
            list: A list of RetentionInfo
        """
        retentions = []
        if 'lifecycle' in bucket_dict and 'rule' in bucket_dict['lifecycle']:
            for lc_item in bucket_dict['lifecycle']['rule']:
                conditions = lc_item['condition']
                action = lc_item['action']
                retention_value = None
                exist_other_conditions = False
                exist_valid_action = False
                if conditions is not None:
                    retention_value = conditions['age']
                    if retention_value is None:
                        if conditions:
                            exist_other_conditions = True
                    elif len(conditions) > 1:
                        exist_other_conditions = True

                if action is not None and 'type' in action:
                    exist_valid_action = (action['type'] == 'Delete')

                new_retention = resource.RetentionInfo(
                    retention=retention_value,
                    exist_valid_action=exist_valid_action,
                    exist_other_conditions=exist_other_conditions)
                retentions.append(new_retention)
        return retentions
