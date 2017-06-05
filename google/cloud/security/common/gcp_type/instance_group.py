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

"""A Compute InstanceGroup.

See:
 https://cloud.google.com/compute/docs/reference/latest/instanceGroups
"""

# pylint: disable=too-few-public-methods
# pylint: disable=too-many-instance-attributes


class InstanceGroup(object):
    """Represents InstanceGroup resource."""

    def __init__(self, **kwargs):
        """InstanceGroup resource."""
        self.creation_timestamp = kwargs.get('creation_timestamp')
        self.description = kwargs.get('description')
        self.name = kwargs.get('name')
        self.named_ports = kwargs.get('named_ports')
        self.network = kwargs.get('network')
        self.region = kwargs.get('region')
        self.size = kwargs.get('size')
        self.subnetwork = kwargs.get('subnetwork')
        self.zone = kwargs.get('zone')

    # TODO: Create utility methods to reconstruct full region, target, and
    # self link.
