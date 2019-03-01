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

"""A Compute InstanceTemplate.

See:
 https://cloud.google.com/compute/docs/reference/latest/instanceTemplates
"""

import json

from google.cloud.forseti.common.gcp_type import key


class InstanceTemplate(object):
    """Represents InstanceTemplate resource."""

    def __init__(self, **kwargs):
        """InstanceTemplate resource.

        Args:
            **kwargs: The object's attributes.
        """
        self.creation_timestamp = kwargs.get('creation_timestamp')
        self.description = kwargs.get('description')
        self.name = kwargs.get('name')
        self.properties = kwargs.get('properties')
        self.id = kwargs.get('id')
        self.project_id = kwargs.get('project_id')
        self._json = kwargs.get('raw_instance_template')

    @classmethod
    def from_dict(cls, instance_template, project_id=None):
        """Creates an InstanceTemplate from an instance template dict.

        Args:
            instance_template (dict): An instance template resource dict.
            project_id (str): A project id for the resource.

        Returns:
            InstanceTemplate: A new InstanceTemplate object.
        """
        kwargs = {'project_id': project_id,
                  'id': instance_template.get('id'),
                  'creation_timestamp': instance_template.get(
                      'creationTimestamp'),
                  'name': instance_template.get('name'),
                  'description': instance_template.get('description'),
                  'properties': instance_template.get('properties', {}),
                  'raw_instance_template': json.dumps(
                      instance_template, sort_keys=True)}

        return cls(**kwargs)

    @staticmethod
    def from_json(json_string, project_id=None):
        """Creates an InstanceTemplate from an instance template JSON string.

        Args:
            json_string (str): A json string representing the instance template.
            project_id (str): A project id for the resource.

        Returns:
            InstanceTemplate: A new InstanceTemplate object.
        """
        instance_template = json.loads(json_string)
        return InstanceTemplate.from_dict(instance_template, project_id)

    def _create_json_str(self):
        """Creates a json string based on the object attributes.

        Returns:
            str: json str.
        """
        resource_dict = {
            'id': self.id,
            'creationTimestamp': self.creation_timestamp,
            'name': self.name,
            'description': self.description,
            'properties': self.properties}

        # Strip out empty values
        resource_dict = dict((k, v) for k, v in resource_dict.items() if v)
        return json.dumps(resource_dict, sort_keys=True)

    @property
    def json(self):
        """Returns the json string representation of the resource.

        Returns:
            str: json str.
        """
        if not self._json:
            self._json = self._create_json_str()

        return self._json

    @property
    def key(self):
        """Returns a Key identifying the object.

        Returns:
            Key: the key
        """
        return Key.from_args(self.project_id, self.name)


KEY_OBJECT_KIND = 'InstanceTemplate'


class Key(key.Key):
    """An identifier for a specific instance template."""

    @staticmethod
    def from_args(project_id, name):
        """Construct a Key from specific values.

        Args:
            project_id (str): project_id
            name (str): name

        Returns:
            Key: the key
        """
        return Key(KEY_OBJECT_KIND, {
            'project_id': project_id,
            'name': name})

    @staticmethod
    def from_url(url):
        """Construct a Key from a URL.

        Args:
            url (str): Object reference URL

        Returns:
            Key: the key

        Raises:
            ValueError: Required parameters are missing.
        """
        obj = Key._from_url(KEY_OBJECT_KIND,
                            {'projects': 'project_id',
                             'instanceTemplates': 'name'},
                            url)
        if not obj.project_id or not obj.name:
            raise ValueError('Missing fields in URL %r' % url)
        return obj

    @property
    def project_id(self):
        """Object property: project_id

        Returns:
            str: project_id
        """
        return self._path_component('project_id')

    @property
    def name(self):
        """Object property: name

        Returns:
            str: name
        """
        return self._path_component('name')
