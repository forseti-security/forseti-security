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

Source or destination
You specify either a source or a destination, but not both, depending 
on the direction of the firewall you create:

For ingress (inbound) rules, the target parameter specifies the destination 
VMs for traffic; you cannot use the destination parameter. You specify 
the source by using the source parameter.

For egress (outbound) rules, the target parameter specifies the source VMs 
for traffic; you cannot use the source parameter. You specify the destination 
by using the destination parameter.

You cannot mix and match service accounts and network tags in any firewall rule:

You cannot use target service accounts and target tags together in any firewall 
rule (ingress or egress).

{
"allowed": [{"IPProtocol": "tcp", "ports": ["50051"]}],
"creationTimestamp": "2018-02-28T21:49:07.739-08:00",
"description": "",
"direction": "INGRESS", 
"disabled": false, 
"id": "1002375335368075964", 
"kind": "compute#firewall", 
"name": "forseti-server-allow-grpc-20180228211432", 
"network": "https://www.googleapis.com/compute/beta/projects/joe-project-p2/global/networks/default", 
"priority": 0, 
"selfLink": "https://www.googleapis.com/compute/beta/projects/joe-project-p2/global/firewalls/forseti-server-allow-grpc-20180228211432", 
"sourceRanges": ["10.128.0.0/9"], 
"targetServiceAccounts": ["forseti-gcp-server-1432@joe-project-p2.iam.gserviceaccount.com"]
}

"""


class FirewallRule(object):
    """Flattened firewall rule."""
    def __init__(self,
                 creation_timestamp,
                 source_ip_addr,
                 source_service_account,
                 source_tag,
                 dest_ip_addr,
                 service_account,
                 tag,
                 action,
                 ip_protocol,
                 ports,
                 direction,
                 disabled,
                 network,
                 full_name,
                 name,
                 org_id):
        self.creation_timestamp = creation_timestamp
        self.source_ip_addr = source_ip_addr
        self.dest_ip_addr = dest_ip_addr
        self.service_account = service_account
        self.source_service_account = source_service_account
        self.source_tag = source_tag
        self.tag = tag
        self.action = action
        self.ip_protocol = ip_protocol
        self.ports = ports
        self.direction = direction
        self.disabled = disabled
        self.network = network
        self.full_name = full_name
        self.org_id = org_id
        self.name = name

    def to_dict(self):
        """Convert to dictionary object.

        Returns:
            dict: Dictionary representation of the object.
        """
        return {
            'creation_timestamp': self.creation_timestamp,
            'source_ip_addr': self.source_ip_addr,
            'source_service_account': self.source_service_account,
            'source_tag': self.source_tag,
            'dest_ip_addr': self.dest_ip_addr,
            'service_account': self.service_account,
            'tag': self.tag,
            'org_id': self.org_id,
            'full_name': self.full_name,
            'action': self.action,
            'ip_protocol': self.ip_protocol,
            'ports': self.ports,
            'network': self.network,
            'direction': self.direction,
            'disabled': self.disabled,
            'name': self.name
        }

    @classmethod
    def from_json(cls, gcp_firewall_rule, resource_full_name, org_id):
        """Generate a list of flattened firewall rule objects based
         on the given firewall resource data in string format.

         Args:
            gcp_firewall_rule (str): Firewall rule resource data,
                in JSON string format.

        Returns:
             list: A list of flattened firewall rule objects.
         """
        json_dict = json.loads(gcp_firewall_rule)

        name = json_dict.get('name')

        action = 'allowed'

        if action not in json_dict:
            action = 'denied'

        # You can only use tag OR service account in a firewall rule.
        is_tag = 'targetTags' in json_dict

        if is_tag:
            identifiers = json_dict.get('targetTags', [])
        else:
            identifiers = json_dict.get('targetServiceAccounts', [])

        direction = json_dict.get('direction')  # INGREE OR EGRESS

        is_ingress = direction.upper() == 'INGRESS'

        is_source_ranges = 'sourceRanges' in json_dict
        is_source_tags = 'sourceTags' in json_dict
        is_source_sa = 'sourceServiceAccounts' in json_dict
        is_dest_ranges = 'destinationRanges' in json_dict

        secondary_identifiers = (
                json_dict.get('sourceRanges') or
                json_dict.get('sourceTags') or
                json_dict.get('sourceServiceAccounts') or
                json_dict.get('destinationRanges'))

        protocol_mappings = json_dict.get(action, [])

        network = json_dict.get('network')

        flattened_firewall_rules = []

        creation_timestamp = json_dict.get('creationTimestamp')
        disabled = False if json_dict.get('disabled') == 'false' else True

        for identifier in identifiers:
            for secondary_identifier in secondary_identifiers:
                for protocol_mapping in protocol_mappings:
                    ip_protocol = protocol_mapping.get('IPProtocol', '')
                    corresponding_ports = protocol_mapping.get('ports', [])
                    for ports in corresponding_ports:
                        # flattened_ports = cls._flatten_ports(corresponding_ports)
                        flattened_firewall_rules.append(
                            FirewallRule(
                                creation_timestamp=creation_timestamp,
                                source_ip_addr=secondary_identifier if is_source_ranges else None,
                                source_service_account=secondary_identifier if is_source_sa else None,
                                source_tag=secondary_identifier if is_source_tags else None,
                                dest_ip_addr=secondary_identifier if is_dest_ranges else None,
                                service_account=identifier if not is_tag else None,
                                tag=identifier if is_tag else None,
                                action=action,
                                ip_protocol=ip_protocol,
                                ports=ports,
                                direction=direction,
                                disabled=disabled,
                                network=network,
                                full_name=resource_full_name,
                                name=name,
                                org_id=org_id
                            ))
        return flattened_firewall_rules

    @classmethod
    def flatten_firewall_rules(cls, firewall_resource_data):
        """Flatten all the gcp firewall rule data.

        Args:
            gcp_firewall_rules (list): A list of firewall rules.

        Returns:
            list: A list of flattened firewall rules.
        """
        results = []
        for gcp_firewall_rule in firewall_resource_data:
            try:
                org_id = 'SAMPLE_ORG'
                full_name = gcp_firewall_rule.get('full_name', '')
                results.extend(cls.from_json(gcp_firewall_rule.get('data', None), full_name, org_id))
            except Exception as e:
                print e
                print gcp_firewall_rule
        return results

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
                flattened_ports += flattened
            else:
                # Single port.
                flattened_ports.append(int(port))

        # Cast the list to set to remove duplicates,
        # and cast it back to list.
        flattened_ports = list(set(flattened_ports))

        # Max port is 65535.
        # if not flattened_ports:
        #    flattened_ports = [i for i in range(0, 65536)]

        return flattened_ports
