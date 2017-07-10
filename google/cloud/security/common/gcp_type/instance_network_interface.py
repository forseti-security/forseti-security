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
"""A Enforced Network Resource."""

import json

# pylint: disable=too-few-public-methods
class InstanceNetworkInterface(object):
    """InstanceNetworkInterface Resource."""

    def __init__(self, network_interface):
        """Initialize

        Args:
            network_interfaces: json from instances on the network_interfaces
        """

        network_dictionary = json.loads(network_interface)
        if len(network_dictionary) > 1:
            LOGGER.error('Should only be one interface ties to an virtual instance.')
        self.kind = network_dictionary[0].get('kind')
        self.network = network_dictionary[0].get('network')
        self.subnetwork = network_dictionary[0].get('subnetwork')
        self.networkIP = network_dictionary[0].get('networkIP')
        self.name = network_dictionary[0].get('name')
        self.accessConfigs = network_dictionary[0].get('accessConfigs')
        self.aliasIpRanges = network_dictionary[0].get('aliasIpRanges')


    def __repr__(self):
        return 'kind: %s Network: %s subnetwork: %s networkIp %s name %s \
            accessConfigs %s aliasIpRanges %s' % (self.kind, self.network, \
            self.subnetwork, self.networkIP, self.name, self.accessConfigs, \
            self.aliasIpRanges)

    def __hash__(self):
        return hash(self.__repr__())

    def __ne__(self, other):
        return (not self.__eq__(other))

    def __eq__(self, other):
        if isinstance(self, InstanceNetworkInterface):
            return ((self.kind == other.kind) and 
                    (self.network == other.network) and 
                    (self.subnetwork == other.subnetwork) and
                    (self.networkIp == other.networkIP) and
                    (self.name == other.name) and 
                    (self.accessConfigs == other.network) and 
                    (self.subnetwork == other.accessConfigs) and
                    (self.alliasIpRanges == other.alliasIpRanges)
                    )
        else:
            return False
