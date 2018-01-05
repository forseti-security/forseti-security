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

"""A Compute Forwarding Rule.

See: https://cloud.google.com/compute/docs/reference/latest/forwardingRules
"""

import json

from google.cloud.forseti.common.util import parser

# pylint: disable=too-many-instance-attributes
class ForwardingRule(object):
    """Represents ForwardRule resource."""

    def __init__(self, **kwargs):
        """Forwarding rule resource.

        Args:
            **kwargs (dict): The object's attributes.
        """
        self.project_id = kwargs.get('project_id')
        self.resource_id = kwargs.get('resource_id')
        self.creation_timestamp = kwargs.get('creation_timestamp')
        self.name = kwargs.get('name')
        self.description = kwargs.get('description')
        self.region = kwargs.get('region')
        self.ip_address = kwargs.get('ip_address')
        self.ip_protocol = kwargs.get('ip_protocol')
        self.port_range = kwargs.get('port_range')
        self.ports = parser.json_unstringify(kwargs.get('ports'))
        self.target = kwargs.get('target')
        self.self_link = kwargs.get('self_link')
        self.load_balancing_scheme = kwargs.get('load_balancing_scheme')
        self.subnetwork = kwargs.get('subnetwork')
        self.network = kwargs.get('network')
        self.backend_service = kwargs.get('backend_service')
        self.json = kwargs.get('raw_json')


    @classmethod
    def from_dict(cls, project_id, forwarding_rule):
        """Returns a new ForwardingRule object from dict.

        Args:
            project_id (str): The project id.
            forwarding_rule (dict): The forwarding rule.

        Returns:
            ForwardingRule: A new ForwardingRule object.
        """
        return cls(
            project_id=project_id,
            resource_id=forwarding_rule.get('id'),
            creation_timestamp=forwarding_rule.get('creationTimestamp', ''),
            name=forwarding_rule.get('name', ''),
            description=forwarding_rule.get('description', ''),
            region=forwarding_rule.get('region', ''),
            ip_address=forwarding_rule.get('IPAddress', ''),
            ip_protocol=forwarding_rule.get('IPProtocol', ''),
            port_range=forwarding_rule.get('portRange', ''),
            ports=forwarding_rule.get('ports', '[]'),
            target=forwarding_rule.get('target', ''),
            self_link=forwarding_rule.get('selfLink', ''),
            load_balancing_scheme=forwarding_rule.get(
                'loadBalancingScheme', ''),
            subnetwork=forwarding_rule.get('subnetwork', ''),
            network=forwarding_rule.get('network', ''),
            backend_service=forwarding_rule.get('backend_service', ''),
            raw_json=json.dumps(forwarding_rule)
        )

    @staticmethod
    def from_json(project_id, forwarding_rule_data):
        """Returns a new ForwardingRule object from json data.

        Args:
            project_id (str): the project id.
            forwarding_rule_data (str): The json data representing
                the forwarding rule.

        Returns:
           ForwardingRule: A new ForwardingRule object.
        """
        forwarding_rule = json.loads(forwarding_rule_data)
        return ForwardingRule.from_dict(project_id, forwarding_rule)

    def __hash__(self):
        """Return hash of properties.

        Returns:
            hash: The hash of the class properties.
        """
        return hash(self.json)
