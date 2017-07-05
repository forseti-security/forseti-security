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


# TODO: The next editor must remove this disable and correct issues.
# pylint: disable=missing-param-doc


class InstanceTemplate(object):
    """Represents InstanceTemplate resource."""

    def __init__(self, **kwargs):
        """InstanceTemplate resource."""
        self.creation_timestamp = kwargs.get('creation_timestamp')
        self.description = kwargs.get('description')
        self.name = kwargs.get('name')
        self.project_id = kwargs.get('project_id')
        self.properties = kwargs.get('properties')
        self.resource_id = kwargs.get('id')

    @property
    def key(self):
        return Key.from_args(self.project_id, self.name)


KEY_OBJECT_KIND = 'InstanceTemplate'


class Key(key.Key):

    @staticmethod
    def from_args(project_id, name):
        return Key(KEY_OBJECT_KIND, {
            'project_id': project_id,
            'name': name})

    @staticmethod
    def from_url(url):
        obj = Key._from_url(KEY_OBJECT_KIND,
                            {'projects': 'project_id',
                             'instanceTemplates': 'name'},
                            url)
        if obj.project_id is None or obj.name is None:
            raise ValueError('Missing fields in URL %r' % url)
        return obj

    @property
    def project_id(self):
        return self._path_component('project_id')

    @property
    def name(self):
        return self._path_component('name')
