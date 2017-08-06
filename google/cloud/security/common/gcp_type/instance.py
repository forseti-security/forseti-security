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

import os
from google.cloud.security.common.gcp_type import key
from google.cloud.security.common.util import parser


# pylint: disable=too-many-instance-attributes
class Instance(object):
    """Represents Instance resource."""

    def __init__(self, **kwargs):
        """Instance resource.

        Args:
            **kwargs (dict): The object's attributes.
        """
        self.can_ip_forward = kwargs.get('can_ip_forward')
        self.cpu_platform = kwargs.get('cpu_platform')
        self.creation_timestamp = kwargs.get('creation_timestamp')
        self.description = kwargs.get('description')
        self.disks = parser.json_unstringify(kwargs.get('disks'))
        self.machine_type = kwargs.get('machine_type')
        self.metadata = parser.json_unstringify(kwargs.get('metadata'))
        self.name = kwargs.get('name')
        self.network_interfaces = parser.json_unstringify(
            kwargs.get('network_interfaces'))
        self.project_id = kwargs.get('project_id')
        self.resource_id = kwargs.get('id')
        self.scheduling = parser.json_unstringify(kwargs.get('scheduling'))
        self.service_accounts = parser.json_unstringify(
            kwargs.get('service_accounts'))
        self.status = kwargs.get('status')
        self.status_message = kwargs.get('status_message')
        self.tags = parser.json_unstringify(kwargs.get('tags'))
        self.zone = kwargs.get('zone')

    @property
    def key(self):
        """Return a Key identifying the object.

        Returns:
            Key: the key
        """
        return Key.from_args(self.project_id, self.zone, self.name)

    def create_network_interfaces(self):
        """Return a list of network_interface objects.

        Returns:
            List: list of InstanceNetworkInterface objects
        """
        return [InstanceNetworkInterface(**ni) for ni in self.network_interfaces]


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
        if zone:
            zone = os.path.basename(zone)
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
        if not obj.project_id or not obj.zone or not obj.name:
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


# pylint: disable=too-few-public-methods
class InstanceNetworkInterface(object):
    """InstanceNetworkInterface Resource."""

    def __init__(self, **kwargs):
        """Initialize

        Args:
            kwargs: json from a single instance on the network_interfaces
        """
        self.kind = kwargs.get('kind')
        self.network = kwargs.get('network')
        self.subnetwork = kwargs.get('subnetwork')
        self.network_ip = kwargs.get('networkIP')
        self.name = kwargs.get('name')
        self.access_configs = kwargs.get('accessConfigs')
        self.alias_ip_ranges = kwargs.get('aliasIpRanges')

    def __repr__(self):
        """Repr

        Returns:
            string: a string for a InstanceNetworkInterface
        """
        return 'kind: %s Network: %s subnetwork: %s network_ip %s name %s' \
            'access_configs %s alias_ip_ranges %s' % (
                self.kind, self.network, self.subnetwork, self.network_ip,
                self.name, self.access_configs, self.alias_ip_ranges)

    def __hash__(self):
        """hash

        Returns:
            hash: of InstanceNetworkInterface
        """
        return hash(self.__repr__())

    def __ne__(self, other):
        """Ne

        Args:
            other (InstanceNetworkInterface): other InstanceNetworkInterface

        Return:
            bool: True if not equal
        """
        return not self.__eq__(other)

    def __eq__(self, other):
        """Eq

        Args:
            other (InstanceNetworkInterface) : other InstanceNetworkInterface

        Return:
            bool: True if is equal
        """
        if isinstance(self, InstanceNetworkInterface):
            return ((self.kind == other.kind) and
                    (self.network == other.network) and
                    (self.subnetwork == other.subnetwork) and
                    (self.network_ip == other.network_ip) and
                    (self.name == other.name) and
                    (self.access_configs == other.access_configs) and
                    (self.alias_ip_ranges == other.alias_ip_ranges))
        return False
