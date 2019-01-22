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


# pylint: disable=too-many-instance-attributes
# pylint: disable=missing-param-doc,missing-type-doc
class KMS(object):
    """A CryptoKey object."""
    def __init__(self, project_id, full_name, display_name, name, unique_id,
                 email, oauth2_client_id, raw_json, keys=None):
        """Initialize."""

        self.project_id = project_id
        self.full_name = full_name
        self.display_name = display_name
        self.name = name
        self.unique_id = unique_id
        self.email = email
        self.oauth2_client_id = oauth2_client_id
        self.keys = keys
        self._json = raw_json

    @classmethod
    def from_dict(cls, project_id, full_name, crypto_key, keys):
        """Returns a new CryptoKey object from dict.

        Args:
            project_id (str): The project id.
            full_name (str): The full path, including ancestors
            crypto_key (dict): CryptoKey dict
            keys (list): A list of dicsts of USER_MANAGED keys for the above
                CryptoKey

        Returns:
            CryptoKey: A new CryptoKey object
        """
        return cls(
            project_id=project_id,
            full_name=full_name,
            display_name=crypto_key.get('displayName'),
            name=crypto_key.get('name'),
            unique_id=crypto_key.get('uniqueId'),
            email=crypto_key.get('email'),
            oauth2_client_id=crypto_key.get('oauth2ClientId'),
            raw_json=json.dumps(crypto_key, sort_keys=True),
            keys=keys,
        )

    @staticmethod
    def from_json(project_id, full_name, crypto_key,
                  crypto_keys=None):
        """Returns a new CryptoKey object from json data.

        Args:
            project_id (str): The project id.
            full_name (str): The full path, including ancestors
            crypto_key (str): The json string representations of the
                CryptoKey
            crypto_keys (list): List of json strings of keys

        Returns:
            CryptoKey: A new CryptoKey object
        """
        service_account = json.loads(crypto_key)
        # Extract out only the key specific attributes
        keys = []
        if crypto_keys:
            keys = KMS.parse_json_keys(crypto_keys)

        return KMS.from_dict(project_id, full_name, service_account,
                                        keys)

    @staticmethod
    def parse_json_keys(crypto_keys):
        """Parse crypto keys in JSON string format.

        Args:
            crypto_keys (list): List of json strings of keys.

        Returns:
            list: A list of service account keys in dictionary format.
        """
        keys = []
        for item in crypto_keys:
            data = json.loads(item.data)
            keys.append({'key_id': item.name,
                         'full_name': item.full_name,
                         'key_algorithm': data.get('keyAlgorithm'),
                         'valid_after_time': data.get('validAfterTime'),
                         'valid_before_time': data.get('validBeforeTime')})
        return keys

    def __repr__(self):
        """String representation.
        Returns:
            str: Json string.
        """
        return self._json

    def __hash__(self):
        """Return hash of properties.
        Returns:
            hash: The hash of the class properties.
        """
        return hash(self._json)
