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

"""A CryptoKey object.

See:
https://cloud.google.com/kms/docs/reference/rest/v1/projects.locations.keyRings#KeyRing
"""

import json

from google.cloud.forseti.common.gcp_type import resource


class KeyRingLifecycleState(resource.LifecycleState):
    """Represents the KeyRing's LifecycleState."""
    pass


class KeyRing(resource.Resource):
    """CryptoKey resource."""

    RESOURCE_NAME_FMT = 'datasets/%s'

    def __init__(
            self,
            key_ring_id,
            full_name=None,
            data=None,
            name=None,
            display_name=None,
            parent=None,
            locations=None,
            lifecycle_state=KeyRingLifecycleState.UNSPECIFIED):
        """Initialize.

        Args:
            key_ring_id (int): The key ring id.
            full_name (str): The full resource name and ancestry.
            data (str): Resource representation of the key ring.
            name (str): The crypto key's unique GCP name, with the
                format "keyring/{id}".
            display_name (str): The key ring's display name.
            locations (List[str]): Locations this key ring resides in. If set,
                there should be exactly one element in the list.
            parent (Resource): The parent Resource.
            lifecycle_state (LifecycleState): The lifecycle state of the
                key ring.
        """
        super(KeyRing, self).__init__(
            resource_id=key_ring_id,
            resource_type=resource.ResourceType.KEYRING,
            name=name,
            display_name=display_name,
            parent=parent,
            locations=locations,
            lifecycle_state=lifecycle_state)
        self.full_name = full_name
        self.data = data

    @classmethod
    def from_json(cls, parent, key_ring_json):
        """Create a crypto key from a JSON object.

        Args:
            parent (Resource): resource this crypto key belongs to.
            json_string(str): JSON string of a crypto key GCP API response.

        Returns:
            CryptoKey: crypto key resource.
        """
        key_ring_dict = json.loads(key_ring_json)
        return cls(
            create_time=key_ring_json.get('createTime', ''),
            name=key_ring_json.get('name', ''),
        )

