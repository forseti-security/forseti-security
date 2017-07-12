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

"""A Compute Instance.

See: https://cloud.google.com/compute/docs/reference/latest/instances
"""


from google.cloud.security.common.gcp_type import key


# pylint: disable=too-many-instance-attributes
class Instance(object):
    """Represents Instance resource."""

    def __init__(self, **kwargs):
        """Instance resource.

        Args:
            kwargs: The object's attributes.
        """
        self.can_ip_forward = kwargs.get('can_ip_forward')
        self.cpu_platform = kwargs.get('cpu_platform')
        self.creation_timestamp = kwargs.get('creation_timestamp')
        self.description = kwargs.get('description')
        self.disks = kwargs.get('disks')
        self.machine_type = kwargs.get('machine_type')
        self.metadata = kwargs.get('metadata')
        self.name = kwargs.get('name')
        self.network_interfaces = kwargs.get('network_interfaces')
        self.project_id = kwargs.get('project_id')
        self.resource_id = kwargs.get('id')
        self.scheduling = kwargs.get('scheduling')
        self.service_accounts = kwargs.get('service_accounts')
        self.status = kwargs.get('status')
        self.status_message = kwargs.get('status_message')
        self.tags = kwargs.get('tags')
        self.zone = kwargs.get('zone')

    @property
    def key(self):
        """Returns a Key identifying the object.

        Returns:
            Key: the key
        """
        return Key.from_args(self.project_id, self.zone, self.name)


KEY_OBJECT_KIND = 'Instance'


class Key(key.Key):
    """An identifier for a specific instance."""

    @staticmethod
    def from_args(project_id, zone, name):
        """Construct a Key from specific values.

        Args:
            project_id (str): project_id
            zone (str): zone
            name (str): name

        Returns:
            Key: the key
        """
        return Key(KEY_OBJECT_KIND, {
            'project_id': project_id,
            'zone': zone,
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
                             'zones': 'zone',
                             'instances': 'name'},
                            url)
        if obj.project_id is None or obj.zone is None or obj.name is None:
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
