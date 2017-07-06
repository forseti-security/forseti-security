# Copyright 2017 Google Inc.
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


from google.cloud.security.common.gcp_type import key


class InstanceTemplate(object):
    """Represents InstanceTemplate resource."""

    def __init__(self, **kwargs):
        """InstanceTemplate resource.

        Args:
            kwargs: The object's attributes.
        """
        self.creation_timestamp = kwargs.get('creation_timestamp')
        self.description = kwargs.get('description')
        self.name = kwargs.get('name')
        self.properties = kwargs.get('properties')
        self.resource_id = kwargs.get('id')
        self.project_id = kwargs.get('project_id')

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
        if obj.project_id is None or obj.name is None:
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
