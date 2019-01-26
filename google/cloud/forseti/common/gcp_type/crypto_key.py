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
https://cloud.google.com/kms/docs/reference/rest/v1/projects.locations.keyRings.cryptoKeys#CryptoKey
"""

import json

from google.cloud.forseti.common.gcp_type import resource


class CryptoKey(resource.Resource):
    """Represents the CryptoKey resource."""

    RESOURCE_NAME_FMT = 'kms_cryptokey/%s'

    def __init__(
            self, crypto_key_id=None, display_name=None, parent=None,
            full_name=None, name=None, primary_version=None, purpose=None,
            create_time=None, next_rotation_time=None, version_template=None,
            labels=None, rotation_period=None, data=None):
        """Initialize.

        Args:
            cryptokey_id (int): The crypto key id.
            full_name (str): The full resource name and ancestry.
            data (str): Resource representation of the crypto key.
            name (str): The crypto key's unique GCP name, with the
                format "cryptokeys/{id}".
            display_name (str): The crypto key's display name.
            parent (Resource): The parent Resource.
        """
        super(CryptoKey, self).__init__(
            resource_id=crypto_key_id,
            resource_type=None,
            # resource_type=resource.ResourceType.KMS_CRYPTOKEY,
            display_name=display_name,
            parent=parent)

            # name=full_name)
#        self.name = name
#        test333 = '3333'
        self.primary_version = primary_version
        self.purpose = purpose
        self.create_time = create_time
        self.next_rotation_time = next_rotation_time
        self.version_template = version_template
        self.labels = labels
        self.rotation_period = rotation_period
        self.data = data
        self._dict = None

    @classmethod
    def from_json(cls, parent, json_string):
        """Returns a new ForwardingRule object from json data.

        Args:
            parent (Resource): resource this crypto key belongs to.
            json_string(str): JSON string of a crypto key GCP API response.

        Returns:
           cryptoKey: A new cryptoKey object.
        """

        key_dict = json.loads(json_string)

        xyz123 = cls(
            parent=parent,
            # full_name=full_name,
            # crypto_key_name=key_dict.get('name'),
            primary_version=key_dict.get('primary', {}),
            purpose=key_dict.get('purpose'),
            create_time=key_dict.get('createTime'),
            next_rotation_time=key_dict.get('nextRotationTime'),
            version_template=key_dict.get('versionTemplate', {}),
            labels=key_dict.get('labels', {}),
            rotation_period=key_dict.get('rotationPeriod'),
            data=json.dumps(key_dict, sort_keys=True),
        )

        return xyz123

    @property
    def as_dict(self):
        """Return the dictionary representation of the crypto key.

        Returns:
            dict: deserialized json object

        """
        if self._dict is None:
            self._dict = json.loads(self.data)

        return self._dict
