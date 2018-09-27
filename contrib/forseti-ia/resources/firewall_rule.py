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

import json

"""
Flatten the following attributes in firewall rules.
IPProtocol, ports,

Example:
"allowed": [{"IPProtocol": "tcp,udp", "ports": ["1","50051"]}]
This will generate 4 Firewall rule objects
- action: allowed, IPProtocol: tcp, ports: 1
- action: allowed, IPProtocol: tcp, ports: 1
- action: allowed, IPProtocol: udp, ports: 50051
- action: allowed, IPProtocol: udp, ports: 50051


"""


DIRECTION_ENCODING = {
    'INGRESS': [0, 1],
    'EGRESS': [1, 0]
}


class FirewallRule(object):
    """Flattened firewall rule."""
    def __init__(self):
        self.creation_timestamp = ''
        # "creationTimestamp": "2018-02-28T21:49:07.739-08:00"
        self.description = ''
        # "description": ""
        self.name = ''
        # "name": "forseti-server-allow-grpc-20180228211432",
        self.priority = 0
        self.source_ranges = []
        self.destination_ranges = []
        self.source_tags = []
        self.target_tags = []
        self.source_service_accounts = []
        self.target_service_accounts = []
        # targetServiceAccounts": ["forseti-gcp-server-1432@joe-project-p2.iam.gserviceaccount.com"]}"
        self.action = ''  # allowed/denied
        self.ip_protocol = ''
        self.ports = ''
        self.direction = ''
        self.disabled = True

    @classmethod
    def from_json(cls, firewall_rule_data):
        """Generate a list of flattened firewall rule objects based
         on the given firewall resource data in string format.

         Args:
            firewall_rule_data (str): Firewall rule resource data,
                in JSON string format.

        Returns:
             list: A list of flattened firewall rule objects.
         """
        # "allowed": [{"IPProtocol": "tcp,udp", "ports": ["1", "50051"]}]
        json_dict = json.loads(firewall_rule_data)

        action = 'allowed'

        if action not in json_dict:
            action = 'denied'

        protocol_mappings = json_dict.get(action, [])

        for protocol_mapping in protocol_mappings:
            ip_protocols = protocol_mapping.get('IPProtocol', [])
            corresponding_ports = protocol_mapping.get('ports', [])

            flattened_ports = cls._flatten_ports(corresponding_ports)

            return [FirewallRule]

        return

    @classmethod
    def _flatten_ports(cls, ports):
        """Flatten the list of ports.

        Example:
            Input: ["1-5", "50051"]
            Output: ["1", "2", "3", "4", "5", "50051"]

        Args:
            corresponding_ports (list): List of corresponding ports.

        Returns:
            list: Flattened ports.
        """

        flattened_ports = []

        # Type of representation that can be in the ports
        # Range - e.g. "0-5"
        # Single port - e.g. "50051"
        # Empty - e.g. [] - this represents all ports.

        for port in ports:
            if '-' in port:
                # This is port range, flatten the range.
                port_range = port.split('-')
                start = int(port_range[0])
                end = int(port_range[1])
                flattened = [i for i in range(start, end+1)]
                flattened_ports += flattened_ports
            else:
                # Single port.
                flattened_ports.append(int(port))

        # Cast the list to set to remove duplicates,
        # and cast it back to list.
        flattened_ports = list(set(flattened_ports))

        if not flattened_ports:
            # Max port is 65535.
            flattened_ports = [i for i in range(0, 65536)]

        return flattened_ports
