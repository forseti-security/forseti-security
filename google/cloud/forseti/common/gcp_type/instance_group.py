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

"""A Compute InstanceGroup.

See:
 https://cloud.google.com/compute/docs/reference/latest/instanceGroups
"""

import json
import os

from google.cloud.forseti.common.gcp_type import key


# pylint: disable=too-many-instance-attributes
class InstanceGroup(object):
    """Represents InstanceGroup resource."""

    def __init__(self, **kwargs):
        """InstanceGroup resource.

        Args:
            **kwargs (dict): The object's attributes.
        """
        self.id = kwargs.get('id')
        self.creation_timestamp = kwargs.get('creation_timestamp')
        self.description = kwargs.get('description')
        self.instance_urls = kwargs.get('instance_urls')
        self.name = kwargs.get('name')
        self.named_ports = kwargs.get('named_ports')
        self.network = kwargs.get('network')
        self.project_id = kwargs.get('project_id')
        self.region = kwargs.get('region')
        self.resource_id = kwargs.get('id')
        self.size = kwargs.get('size')
        self.subnetwork = kwargs.get('subnetwork')
        self.zone = kwargs.get('zone')
        self.project_id = kwargs.get('project_id')
        self._json = kwargs.get('raw_instance_group')

    @classmethod
    def from_dict(cls, instance_group, project_id=None):
        """Creates an InstanceGroup from an instance group dict.

        Args:
            instance_group (dict): An instance group resource dict.
            project_id (str): A project id for the resource.

        Returns:
            InstanceGroup: A new InstanceGroup object.
        """
        kwargs = {'project_id': project_id,
                  'id': instance_group.get('id'),
                  'creation_timestamp': instance_group.get('creationTimestamp'),
                  'name': instance_group.get('name'),
                  'description': instance_group.get('description'),
                  'instance_urls': instance_group.get('instance_urls', []),
                  'named_ports': instance_group.get('namedPorts', []),
                  'network': instance_group.get('network'),
                  'region': instance_group.get('region'),
                  'size': instance_group.get('size'),
                  'subnetwork': instance_group.get('subnetwork'),
                  'zone': instance_group.get('zone'),
                  'raw_instance_group': json.dumps(
                      instance_group, sort_keys=True)}

        return cls(**kwargs)

    @staticmethod
    def from_json(json_string, project_id=None):
        """Creates an InstanceGroup from an instance group JSON string.

        Args:
            json_string (str): A json string representing the instance group.
            project_id (str): A project id for the resource.

        Returns:
            InstanceGroup: A new InstanceGroup object.
        """
        instance_group = json.loads(json_string)
        return InstanceGroup.from_dict(instance_group, project_id)

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
            'instance_urls': self.instance_urls,
            'namedPorts': self.named_ports,
            'network': self.network,
            'region': self.region,
            'size': self.size,
            'subnetwork': self.subnetwork,
            'zone': self.zone}

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
        if region:
            region = os.path.basename(region)
        if zone:
            zone = os.path.basename(zone)
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
        if (not obj.project_id or
                not obj.name or
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
