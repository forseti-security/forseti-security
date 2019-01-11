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

"""Lien Resource."""

import json

from google.cloud.forseti.common.gcp_type import resource

_NAME_PREFIX = 'liens/'


class Lien(resource.Resource):
    """Lien Resource."""

    def __init__(self, parent, name, restrictions, raw_json):
        """Initialize a Lien.

        Args:
            parent (Resource): resource this lien belongs to.
            name (str): name of the lien.
            restrictions (List[str]): restrictions this lien protects against.
            raw_json (str): raw json of this lien.
        """
        super(Lien, self).__init__(
            resource_id=name,
            resource_type=resource.ResourceType.LIEN,
            name='{}/liens/{}'.format(parent.name, name),
            display_name=name,
            parent=parent)
        self.full_name = '{}lien/{}/'.format(parent.full_name, name)
        self.restrictions = restrictions
        self.raw_json = raw_json

    @classmethod
    def from_json(cls, parent, json_string):
        """Create a lien from a json string.

        Args:
            parent (Resource): resource this lien belongs to.
            json_string (str): json string of a lien GCP API response.

        Returns:
            Lien: lien resource.
        """
        lien_dict = json.loads(json_string)
        name = lien_dict['name']
        if name.startswith(_NAME_PREFIX):
            name = name[len(_NAME_PREFIX):]
        return cls(
            parent=parent,
            name=name,
            restrictions=lien_dict['restrictions'],
            raw_json=json_string,
        )
