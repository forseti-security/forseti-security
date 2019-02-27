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

"""A KeyRing object.

See:
https://cloud.google.com/kms/docs/reference/rest/v1/projects.locations.keyRings#KeyRing
"""

import json

from google.cloud.forseti.common.gcp_type import resource


class KeyRing(resource.Resource):
    """KeyRing resource."""

    # pylint: disable=expression-not-assigned
    def __init__(self, key_ring_name=None, key_ring_full_name=None,
                 key_ring_parent_type_name=None, key_ring_type=None,
                 create_time=None, name=None, data=None):
        """Initialize.

        Args:
            key_ring_name (str): The unique KeyRing id.
            key_ring_full_name (str): The KeyRing full name.
            key_ring_parent_type_name (Resource): Resource this KeyRing belongs
            to.
            key_ring_type (str): The KeyRing type name.
            create_time (str): The key ring's display name.
            name (str): The unique KeyRing name.
            data (Resource): KeyRing resource data.
        """
        super(KeyRing, self).__init__(
            resource_id=key_ring_name,
            name=key_ring_full_name,
            parent=key_ring_parent_type_name,
            resource_type=resource.ResourceType.KEY_RING),
        self.key_ring_type = key_ring_type,
        self.create_time = create_time,
        self.name = name,
        self.data = data

    @classmethod
    def from_json(cls, key_ring_name, key_ring_full_name,
                  key_ring_parent_type_name, key_ring_type, json_string):
        """Create a KeyRing from a JSON object.

        Args:
            key_ring_name (str): The unique KeyRing id.
            key_ring_full_name (str): The KeyRing full name.
            key_ring_parent_type_name (str): The KeyRing parent type name.
            key_ring_type (str): The KeyRing type name.
            json_string(str): JSON string of a KeyRing GCP API response.

        Returns:
            KeyRing: A new KeyRing object.
        """
        key_ring_dict = json.loads(json_string)

        return cls(
            key_ring_name=key_ring_name,
            key_ring_full_name=key_ring_full_name,
            key_ring_parent_type_name=key_ring_parent_type_name,
            key_ring_type=key_ring_type,
            create_time=key_ring_dict.get('createTime'),
            name=key_ring_dict.get('name'),
            data=json.dumps(key_ring_dict, sort_keys=True)
        )
