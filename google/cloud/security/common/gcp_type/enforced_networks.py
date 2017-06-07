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
class EnfocedNetworks(object):
    """Enfoced Networks Resource."""

    def __init__(self, project, network, enforced_networks,
                 project_number=None):
        """Initialize

        Args:
            project: string of gcp project
            network: network in the projct
            enforced_network: network enforced by the project
        """
        self.project = project
        self.network = network
        self.enfoced_networks = enforced_networks

    def __hash__(self):
        """Return hash of properties."""
        return hash(self.project, self.network, self.enforced_networks)
