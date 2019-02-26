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
from google.cloud.forseti.common.util import logger


LOGGER = logger.get_logger(__name__)


class CryptoKey(resource.Resource):
    """Represents the CryptoKey resource."""

    # pylint: disable=too-many-instance-attributes, too-many-arguments, expression-not-assigned
    def __init__(
            self, crypto_key_name=None, crypto_key_full_name=None,
            crypto_key_parent_type_name=None, crypto_key_type=None,
            primary_version=None, purpose=None, create_time=None,
            next_rotation_time=None, version_template=None, labels=None,
            rotation_period=None, data=None):
        """Initialize.

        Args:
            crypto_key_name (str): The unique Cryptokey id.
            crypto_key_full_name (str): The Cryptokey full name.
            crypto_key_parent_type_name (Resource): Resource this Cryptokey
            belongs to.
            crypto_key_type (str): The Cryptokey type name.
            primary_version (dict): Primary Cryptokey version.
            purpose (enum): Immutable purpose of this Cryptokey.
            create_time (str): The time at which this Cryptokey was created.
            next_rotation_time (str): Time when the Cryptokey rotates.
            version_template (dict): Cryptokey version setting details.
            labels (dict): User-defined metadata.
            rotation_period (str): Scheduled rotation period of CryptoKey.
            data (Resource): Cryptokey resource data.
        """
        super(CryptoKey, self).__init__(
            resource_id=crypto_key_name,
            name=crypto_key_name,
            parent=crypto_key_parent_type_name,
            resource_type=resource.ResourceType.CRYPTO_KEY),
        self.crypto_key_full_name = crypto_key_full_name
        self.crypto_key_type = crypto_key_type
        self.primary_version = primary_version
        self.purpose = purpose
        self.create_time = create_time
        self.next_rotation_time = next_rotation_time
        self.version_template = version_template
        self.labels = labels
        self.rotation_period = rotation_period
        self.data = data

    @classmethod
    def from_json(cls, crypto_key_name, crypto_key_full_name,
                  crypto_key_parent_type_name, crypto_key_type, json_string):
        """Returns a new CryptoKey object from a JSON object.

        Args:
            crypto_key_name (str): The unique Cryptokey id.
            crypto_key_full_name (str): The Cryptokey full name.
            crypto_key_parent_type_name (str): The Cryptokey parent type name.
            crypto_key_type (str): The Cryptokey type name.
            json_string(str): JSON string of a Cryptokey GCP API response.

        Returns:
           CryptoKey: A new CryptoKey object.
        """
        key_dict = json.loads(json_string)

        return cls(
            crypto_key_name=crypto_key_name,
            crypto_key_full_name=crypto_key_full_name,
            crypto_key_parent_type_name=crypto_key_parent_type_name,
            crypto_key_type=crypto_key_type,
            primary_version=key_dict.get('primary', {}),
            purpose=key_dict.get('purpose'),
            create_time=key_dict.get('createTime'),
            next_rotation_time=key_dict.get('nextRotationTime'),
            version_template=key_dict.get('versionTemplate', {}),
            labels=key_dict.get('labels', {}),
            rotation_period=key_dict.get('rotationPeriod'),
            data=json.dumps(key_dict, sort_keys=True),
        )
