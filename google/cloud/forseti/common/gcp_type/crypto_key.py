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
https://cloud.google.com/kms/docs/reference/rest/v1/projects.locations.keyRings.cryptoKeys#CryptoKey
"""

import json

from google.cloud.forseti.common.gcp_type import resource


class CryptoKeyLifecycleState(resource.LifecycleState):
    """Represents the CryptoKey's LifecycleState."""
    pass


class CryptoKey(resource.Resource):
    """CryptoKey resource."""

    def __init__(
            self,
            crypto_key_id,
            full_name=None,
            data=None,
            name=None,
            display_name=None,
            parent=None,
            locations=None,
            lifecycle_state=CryptoKeyLifecycleState.UNSPECIFIED):
        """Initialize.

        Args:
            cryptokey_id (int): The crypto key id.
            full_name (str): The full resource name and ancestry.
            data (str): Resource representation of the crypto key.
            name (str): The crypto key's unique GCP name, with the
                format "cryptokeys/{id}".
            display_name (str): The crypto key's display name.
            locations (List[str]): Locations this crypto key resides in. If set,
                there should be exactly one element in the list.
            parent (Resource): The parent Resource.
            lifecycle_state (LifecycleState): The lifecycle state of the
                crypto key.
        """
        super(CryptoKey, self).__init__(
            resource_id=crypto_key_id,
            resource_type=resource.ResourceType.CRYPTOKEY,
            name=name,
            display_name=display_name,
            parent=parent,
            locations=locations,
            lifecycle_state=lifecycle_state)
        self.full_name = full_name
        self.data = data

    # @classmethod
    # def from_dict(cls, parent, crypto_key_dict):
    #     """Returns a new CryptoKey object from dict.
    #
    #     Args:
    #         parent (Resource): The parent resource of this key.
    #         crypto_key_dict (dict): CryptoKey dictionary.
    #
    #     Returns:
    #         CryptoKey: A new CryptoKey object.
    #     """
    #     return cls(
    #         create_time=crypto_key_dict.get('createTime', ''),
    #         name=crypto_key_dict.get('name', ''),
    #         next_rotation_time=crypto_key_dict.get('nextRotationTime', ''),
    #         primary_algorithm=crypto_key_dict.get('primary').get('algorithm'),
    #         primary_create_time=crypto_key_dict.get('primary').get('createTime'),
    #         primary_generate_time=crypto_key_dict.get('primary').get('generateTime'),
    #         primary_name=crypto_key_dict.get('primary').get('name'),
    #         protection_level=crypto_key_dict.get('primary').get('protectionLevel'),
    #         state=crypto_key_dict.get('primary').get('state'),
    #         purpose=crypto_key_dict.get('purpose', ''),
    #         rotationPeriod=crypto_key_dict.get('rotationPeriod', ''),
    #         version_algorithm=crypto_key_dict.get('versionTemplate').get('algorithm', ''),
    #         version_protection_level=crypto_key_dict.get('versionTemplate').get('protectionLevel', '')
    #     )

    @classmethod
    def from_json(cls, parent, crypto_key_json):
        """Create a crypto key from a JSON object.

        Args:
            parent (Resource): resource this crypto key belongs to.
            json_string(str): JSON string of a crypto key GCP API response.

        Returns:
            CryptoKey: crypto key resource.
        """
        crypto_key_dict = json.loads(crypto_key_json)
        return cls(
            create_time=crypto_key_dict.get('createTime', ''),
            name=crypto_key_dict.get('name', ''),
            next_rotation_time=crypto_key_dict.get('nextRotationTime', ''),
            primary_algorithm=crypto_key_dict.get('primary').get('algorithm'),
            primary_create_time=crypto_key_dict.get('primary').get('createTime'),
            primary_generate_time=crypto_key_dict.get('primary').get('generateTime'),
            primary_name=crypto_key_dict.get('primary').get('name'),
            protection_level=crypto_key_dict.get('primary').get('protectionLevel'),
            state=crypto_key_dict.get('primary').get('state'),
            purpose=crypto_key_dict.get('purpose', ''),
            rotationPeriod=crypto_key_dict.get('rotationPeriod', ''),
            version_algorithm=crypto_key_dict.get('versionTemplate').get('algorithm', ''),
            version_protection_level=crypto_key_dict.get('versionTemplate').get('protectionLevel', '')
        )

