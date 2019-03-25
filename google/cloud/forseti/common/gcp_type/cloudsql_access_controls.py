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

"""A CloudSQL ACL Resource."""

import json


class CloudSqlAccessControl(object):
    """CloudSQL IP Configuration (access ACLs) Resource."""

    def __init__(self, project_id, instance_name, full_name, ipv4_enabled,
                 authorized_networks, require_ssl, raw_json):
        """Initialize.

        Args:
            project_id (str): The project id.
            instance_name (str): CloudSQL instance name
            full_name (str): The full resource name and ancestory.
            ipv4_enabled (bool): True if IP access is enabled for the instance.
            authorized_networks (list): Authorized networks for CloudSQL
                instance.
            require_ssl (bool): Only SSL connections allowed.
            raw_json (str): The raw json string for the acl.
        """
        self.project_id = project_id
        self.instance_name = instance_name
        self.full_name = full_name
        self.ipv4_enabled = ipv4_enabled
        self.authorized_networks = authorized_networks
        self.require_ssl = require_ssl
        self.json = raw_json

    @classmethod
    def from_dict(cls, project_id, instance_name, full_name, acl):
        """Returns a new CloudSqlAccessControl object from dict.

        Args:
            project_id (str): The project id.
            instance_name (str): The CloudSQL instance name.
            full_name (str): The full resource name and ancestory.
            acl (dict): The CloudSQL ACL.

        Returns:
            CloudSqlAccessControl: A new CloudSqlAccessControl object.
        """
        networks = [network['value']
                    for network in acl.get('authorizedNetworks', [])]
        return cls(
            project_id=project_id,
            instance_name=instance_name,
            full_name=full_name,
            ipv4_enabled=acl.get('ipv4Enabled', False),
            authorized_networks=networks,
            require_ssl=acl.get('requireSsl', False),
            raw_json=json.dumps(acl, sort_keys=True)
        )

    @staticmethod
    def from_json(project_id, full_name, instance_data):
        """Returns a new CloudSqlAccessControl object from json data.

        Args:
            project_id (str): the project id.
            full_name (str): The full resource name and ancestory.
            instance_data (str): The json data for the CloudSQL instance.

        Returns:
            CloudSqlAccessControl: A new CloudSqlAccessControl object.
        """
        instance = json.loads(instance_data)
        return CloudSqlAccessControl.from_dict(
            project_id, instance['name'], full_name,
            instance['settings'].get('ipConfiguration', {}))

    def __hash__(self):
        """Return hash of properties.

        Returns:
            hash: The hash of the class properties.
        """
        return hash(frozenset({self.project_id, self.instance_name, self.json}))
