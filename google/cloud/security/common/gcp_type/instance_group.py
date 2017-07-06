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


# pylint: disable=too-many-instance-attributes
class InstanceGroup(object):
    """Represents InstanceGroup resource."""

    def __init__(self, **kwargs):
        """InstanceGroup resource.

        Args:
            kwargs: The object's attributes.
        """
        self.creation_timestamp = kwargs.get('creation_timestamp')
        self.description = kwargs.get('description')
        self.name = kwargs.get('name')
        self.named_ports = kwargs.get('named_ports')
        self.network = kwargs.get('network')
        self.region = kwargs.get('region')
        self.size = kwargs.get('size')
        self.subnetwork = kwargs.get('subnetwork')
        self.zone = kwargs.get('zone')
        self.project_id = kwargs.get('project_id')

    @property
    def key(self):
        """Returns a Key identifying the object.

        Returns:
            Key: the key
        """
        return Key.from_args(self.project_id, self.name,
                             region=self.region,
                             zone=self.zone)


KEY_OBJECT_KIND = 'InstanceGroup'


class Key(key.Key):
    """An identifier for a specific instance group."""

    @staticmethod
    def from_args(project_id, name, region=None, zone=None):
        """Construct a Key from specific values.

        One and only one of (region, zone) must be specified.

        Args:
            project_id (str): project_id
            name (str): name
            region (str): region
            zone (str): zone

        Returns:
            Key: the key

        Raises:
            ValueError: an invalid combination of arguments was provided.
        """
        if not bool(region) ^ bool(zone):
            raise ValueError('Key must specify one of either region or zone')
        return Key(KEY_OBJECT_KIND, {
            'project_id': project_id,
            'region': region,
            'zone': zone,
            'name': name})

    @classmethod
    def from_url(cls, url):
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
                             'regions': 'region',
                             'zones': 'zone',
                             'instanceGroups': 'name'},
                            url)
        if (obj.project_id is None or
                obj.name is None or
                not bool(obj.zone) ^ bool(obj.region)):
            raise ValueError('Invalid fields in URL %r' % url)
        return obj

    @property
    def project_id(self):
        """Object property: project_id

        Returns:
            str: project_id
        """
        return self._path_component('project_id')

    @property
    def region(self):
        """Object property: region

        Returns:
            str: region
        """
        return self._path_component('region')

    @property
    def zone(self):
        """Object property: zone

        Returns:
            str: zone
        """
        return self._path_component('zone')

    @property
    def name(self):
        """Object property: name

        Returns:
            str: name
        """
        return self._path_component('name')
