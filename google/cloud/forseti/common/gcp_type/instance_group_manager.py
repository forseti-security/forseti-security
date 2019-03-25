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

"""A Compute InstanceGroupManager.

See:
 https://cloud.google.com/compute/docs/reference/latest/instanceGroupManagers
"""

import json


# pylint: disable=too-many-instance-attributes
class InstanceGroupManager(object):
    """Represents InstanceGroupManager resource."""

    def __init__(self, **kwargs):
        """InstanceGroupManager resource.

        Args:
            **kwargs (dict): Keyworded variable args.
        """
        self.id = kwargs.get('id')
        self.base_instance_name = kwargs.get('base_instance_name')
        self.creation_timestamp = kwargs.get('creation_timestamp')
        self.description = kwargs.get('description')
        self.current_actions = kwargs.get('current_actions')
        self.instance_group = kwargs.get('instance_group')
        self.instance_template = kwargs.get('instance_template')
        self.name = kwargs.get('name')
        self.named_ports = kwargs.get('named_ports')
        self.project_id = kwargs.get('project_id')
        self.region = kwargs.get('region')
        self.resource_id = kwargs.get('id')
        self.target_pools = kwargs.get('target_pools')
        self.target_size = kwargs.get('target_size')
        self.zone = kwargs.get('zone')
        self._json = kwargs.get('raw_instance_group_manager')

    @classmethod
    def from_dict(cls, igm, project_id=None):
        """Creates an InstanceGroupManager from an instance group manager dict.

        Args:
            igm (dict): An instance group manager resource dict.
            project_id (str): A project id for the resource.

        Returns:
            InstanceGroupManager: A new InstanceGroupManager object.
        """
        kwargs = {'project_id': project_id,
                  'id': igm.get('id'),
                  'creation_timestamp': igm.get('creationTimestamp'),
                  'name': igm.get('name'),
                  'description': igm.get('description'),
                  'base_instance_name': igm.get('baseInstanceName'),
                  'current_actions': igm.get('currentActions', {}),
                  'instance_group': igm.get('instanceGroup'),
                  'instance_template': igm.get('instanceTemplate'),
                  'named_ports': igm.get('namedPorts', []),
                  'region': igm.get('region'),
                  'target_pools': igm.get('targetPools', []),
                  'target_size': igm.get('targetSize'),
                  'zone': igm.get('zone'),
                  'raw_instance_group_manager': json.dumps(
                      igm, sort_keys=True)}

        return cls(**kwargs)

    @staticmethod
    def from_json(json_string, project_id=None):
        """Creates an InstanceGroupManager from a JSON string.

        Args:
            json_string (str): A json string representing the instance group
                manager.
            project_id (str): A project id for the resource.

        Returns:
            InstanceGroupManager: A new InstanceGroupManager object.
        """
        igm = json.loads(json_string)
        return InstanceGroupManager.from_dict(igm, project_id)

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
            'baseInstanceName': self.base_instance_name,
            'currentActions': self.current_actions,
            'instanceGroup': self.instance_group,
            'instanceTemplate': self.instance_template,
            'namedPorts': self.named_ports,
            'targetPools': self.target_pools,
            'targetSize': self.target_size,
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

    # TODO: Create utility methods to reconstruct full region, target, and
    # self link.
