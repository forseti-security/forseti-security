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

"""A Compute InstanceGroup.

See:
 https://cloud.google.com/compute/docs/reference/latest/instanceGroups
"""


from google.cloud.security.common.gcp_type import key


# TODO: The next editor must remove this disable and correct issues.
# pylint: disable=missing-param-doc


# pylint: disable=too-many-instance-attributes
class InstanceGroup(object):
    """Represents InstanceGroup resource."""

    def __init__(self, **kwargs):
        """InstanceGroup resource."""
        self.creation_timestamp = kwargs.get('creation_timestamp')
        self.description = kwargs.get('description')
        self.name = kwargs.get('name')
        self.named_ports = kwargs.get('named_ports')
        self.network = kwargs.get('network')
        self.region = kwargs.get('region')
        self.size = kwargs.get('size')
        self.subnetwork = kwargs.get('subnetwork')
        self.zone = kwargs.get('zone')

    @property
    def key(self):
        return Key.from_args(self.project_id, self.name,
                             region=self.region,
                             zone=self.zone)


KEY_OBJECT_KIND = 'InstanceGroup'


class Key(key.Key):

    @staticmethod
    def from_args(project_id, name, region=None, zone=None):
        if not bool(region) ^ bool(zone):
            raise ValueError('Key must specify one of either region or zone')
        return Key(KEY_OBJECT_KIND, {
            'project_id': project_id,
            'region': region,
            'zone': zone,
            'name': name})

    @classmethod
    def from_url(cls, url):
        obj = Key._from_url(KEY_OBJECT_KIND,
                            {'projects': 'project_id',
                             'regions': 'region',
                             'zones': 'zone',
                             'instanceGroups': 'name'},
                            url)
        if (obj.project_id is None or
                obj.name is None or
                not (bool(obj.zone) ^ bool(obj.region))):
            raise ValueError('Invalid fields in URL %r' % url)
        return obj

    @property
    def project_id(self):
        return self._path_component('project_id')

    @property
    def region(self):
        return self._path_component('region')

    @property
    def zone(self):
        return self._path_component('zone')

    @property
    def name(self):
        return self._path_component('name')
