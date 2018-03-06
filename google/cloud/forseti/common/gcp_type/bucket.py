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
            lifecycle_state=BucketLifecycleState.UNSPECIFIED):
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
        """
        super(Bucket, self).__init__(
            resource_id=bucket_id,
            resource_type=resource.ResourceType.BUCKET,
            name=name,
            display_name=display_name,
            parent=parent,
            lifecycle_state=lifecycle_state)
        self.full_name = full_name
        self.data = data
