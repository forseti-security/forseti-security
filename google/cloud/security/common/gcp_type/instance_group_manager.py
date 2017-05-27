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

"""A Compute InstanceGroupManager.

See:
 https://cloud.google.com/compute/docs/reference/latest/instanceGroupManagers
"""

# pylint: disable=too-few-public-methods
# pylint: disable=too-many-instance-attributes


class InstanceGroupManager(object):
    """Represents InstanceGroupManager resource."""

    def __init__(self, **kwargs):
        """InstanceGroupManager resource."""
        self.base_instance_name = kwargs.get('base_instance_name')
        self.creation_timestamp = kwargs.get('creation_timestamp')
        self.description = kwargs.get('description')
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

    # TODO: Create utility methods to reconstruct full region, target, and
    # self link.
