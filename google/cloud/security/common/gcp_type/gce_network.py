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


# pylint: disable=too-few-public-methods
class GceNetwork(object):
    """Enfoced Networks Resource."""

    def __init__(self, project, network, is_external_network):
        """Initialize

        Args:
            project: string of gcp project
            network: network in the projct
        """
        self.project = project
        self.network = network
        self.is_external_network = is_external_network

    def __repr__(self):
        return 'Project: %s Network: %s is_external: %s' % (self.project, self.network, self.is_external_network)

    def __hash__(self):
        return hash(self.__repr__())

    def __ne__(self, other):
        return (not self.__eq__(other))

    def __eq__(self, other):
        if isinstance(self, GceNetwork):
            return ((self.project == other.project) and 
                    (self.network == other.network) and 
                    (self.is_external_network == other.is_external_network))
        else:
            return False
