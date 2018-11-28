# Copyright 2018 The Forseti Security Authors. All rights reserved.
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
"""A Table Resource.

See: https://cloud.google.com/storage/docs/json_api/v1/
"""

import json

from google.cloud.forseti.common.gcp_type import resource

class Table(resource.Resource):
    """Table resource."""

    RESOURCE_NAME_FMT = 'tables/%s'

    def __init__(
            self,
            table_id,
            data=None,
            parent=None):
        """Initialize.

        Args:
            table_id (int): The table id.
            full_name (str): The full resource name and ancestry.
            data (str): Resource representation of the bucket.
            name (str): The bucket's unique GCP name, with the
                format "buckets/{id}".
            display_name (str): The bucket's display name.
            locations (List[str]): Locations this bucket resides in. If set,
                there should be exactly one element in the list.
            parent (Resource): The parent Resource.
            lifecycle_state (LifecycleState): The lifecycle state of the
                bucket.
        """
        super(Table, self).__init__(
            resource_id=table_id,
            resource_type=resource.ResourceType.TABLE,
            parent=parent)
        if self.parent:
            type_name = self.type + '/' + self.id + '/'
            self.full_name = self.parent.full_name + type_name
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
        table_dict = json.loads(json_string)
        table_id = table_dict['tableReference']['datasetId']
        return cls(
            table_id=table_id,
            parent=parent,
            data=json_string,
        )
