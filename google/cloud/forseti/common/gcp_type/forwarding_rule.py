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


# pylint: disable=too-many-arguments
# pylint: disable=too-many-instance-attributes
# pylint: disable=too-many-locals
class ForwardingRule(object):
    """Represents ForwardRule resource."""

    def __init__(self, project_id, resource_id, full_name, creation_timestamp,
                 name, description, region, ip_address, ip_protocol, port_range,
                 ports, target, self_link, load_balancing_scheme,
                 subnetwork, network, backend_service, raw_json):
        """Forwarding rule resource.

        Args:
            project_id (str): The project containing the forwarding rule.
            resource_id (str): The id of the forwarding rule.
            full_name (str): The full resource name and ancestory.
            creation_timestamp (str): Timestampe when the forwarding rule was
                created.
            name (str): The name of the forwarding rule.
            description (str): Description of the forwarding rule.
            region (str): The region where this forwarding rule resides.
            ip_address (str): The IP address to match.
            ip_protocol (strin): The IP protocol to match.
            port_range (str): Port range, ranging from low to high,
                for which this forwarding rule matches.
            ports (list): List of ports for which this forwarding rule matches.
            target (str): The target for which this forwarding rule matches.
            self_link (str): self link
            load_balancing_scheme (str): load balancing scheme
            subnetwork (str): subnetwork
            network (str): network
            backend_service (str): backend service
            raw_json (str): The raw json string for the forwarding rule.
        """
        self.project_id = project_id
        self.resource_id = resource_id
        self.full_name = full_name
        self.creation_timestamp = creation_timestamp
        self.name = name
        self.description = description
        self.region = region
        self.ip_address = ip_address
        self.ip_protocol = ip_protocol
        self.port_range = port_range
        self.ports = ports
        self.target = target
        self.self_link = self_link
        self.load_balancing_scheme = load_balancing_scheme
        self.subnetwork = subnetwork
        self.network = network
        self.backend_service = backend_service
        self._json = raw_json

    @classmethod
    def from_dict(cls, project_id, full_name, forwarding_rule):
        """Returns a new ForwardingRule object from dict.

        Args:
            project_id (str): The project id.
            full_name (str): The full resource name and ancestory.
            forwarding_rule (dict): The forwarding rule.

        Returns:
            ForwardingRule: A new ForwardingRule object.
        """
        return cls(
            project_id=project_id,
            resource_id=forwarding_rule.get('id'),
            full_name=full_name,
            creation_timestamp=forwarding_rule.get('creationTimestamp', ''),
            name=forwarding_rule.get('name', ''),
            description=forwarding_rule.get('description', ''),
            region=forwarding_rule.get('region', ''),
            ip_address=forwarding_rule.get('IPAddress', ''),
            ip_protocol=forwarding_rule.get('IPProtocol', ''),
            port_range=forwarding_rule.get('portRange', ''),
            ports=forwarding_rule.get('ports', []),
            target=forwarding_rule.get('target', ''),
            self_link=forwarding_rule.get('selfLink', ''),
            load_balancing_scheme=forwarding_rule.get(
                'loadBalancingScheme', ''),
            subnetwork=forwarding_rule.get('subnetwork', ''),
            network=forwarding_rule.get('network', ''),
            backend_service=forwarding_rule.get('backend_service', ''),
            raw_json=json.dumps(forwarding_rule, sort_keys=True)
        )

    @staticmethod
    def from_json(project_id, full_name, forwarding_rule_data):
        """Returns a new ForwardingRule object from json data.

        Args:
            project_id (str): the project id.
            full_name (str): The full resource name and ancestory.
            forwarding_rule_data (str): The json data representing
                the forwarding rule.

        Returns:
           ForwardingRule: A new ForwardingRule object.
        """
        forwarding_rule = json.loads(forwarding_rule_data)
        return ForwardingRule.from_dict(project_id, full_name, forwarding_rule)

    def __repr__(self):
        """String representation.
        Returns:
            str: Json string.
        """
        return self._json

    def __hash__(self):
        """Return hash of properties.

        Returns:
            hash: The hash of the class properties.
        """
        return hash(self._json)
