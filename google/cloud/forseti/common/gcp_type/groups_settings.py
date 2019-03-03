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


class GroupsSettings(resource.Resource): #TODO ensure id and type are set in a way that they match what its put into the rules map in the engine
    """Represents the CryptoKey resource."""

    # pylint: disable=too-many-instance-attributes, too-many-arguments, expression-not-assigned
    def __init__(
            self, email, whoCanAdd=None, whoCanJoin=None, whoCanViewMembership=None,
            whoCanViewGroup=None, whoCanInvite=None, 
            allowExternalMembers=None, whoCanLeaveGroup=None):
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
        super(GroupsSettings, self).__init__(
            resource_id=email,
            name=email,
            resource_type=resource.ResourceType.GROUPS_SETTINGS),

        
        self.whoCanAdd = whoCanAdd
        self.whoCanJoin = whoCanJoin
        self.whoCanViewMembership = whoCanViewMembership
        self.whoCanViewGroup = whoCanViewGroup
        self.whoCanInvite = whoCanInvite
        self.allowExternalMembers = bool(allowExternalMembers)
        self.whoCanLeaveGroup = whoCanLeaveGroup

    @classmethod
    def from_json(cls, email, settings):
        settings = json.loads(settings)
        return cls(
            email=email, 
            whoCanAdd=settings["whoCanAdd"], 
            whoCanJoin=settings["whoCanJoin"],
            whoCanViewMembership=settings["whoCanViewMembership"],
            whoCanViewGroup=settings["whoCanViewGroup"],
            whoCanInvite=settings["whoCanInvite"],
            allowExternalMembers=settings["allowExternalMembers"],
            whoCanLeaveGroup=settings["whoCanLeaveGroup"]
            )
