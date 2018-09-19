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


class Lien(resource.Resource):
    """Lien Resource."""

    def __init__(self, parent, name, restrictions, raw_json):
        """Initialize a Lien.

        Args:
            parent (Resource): id of the project this lien belongs to.
            name (str): name of the lien.
            restrictions (List[str]): restrictions this lien protects against.
            raw_json (str): raw json of this lien.
        """
        super(Lien, self).__init__(
            resource_id=name,
            resource_type=resource.ResourceType.LIEN,
            name='{}/{}'.format(parent.name, name),
            display_name=name,
            parent=parent)
        self.restrictions = restrictions
        self.raw_json = raw_json

    @classmethod
    def from_json(cls, parent, json_string):
        lien_dict = json.loads(json_string)
        return cls(
            parent=parent,
            name=lien_dict.get('name'),
            restrictions=lien_dict.get('restrictions'),
            raw_json=json_string,
        )
