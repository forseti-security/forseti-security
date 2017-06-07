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

"""A Compute Instance.

See: https://cloud.google.com/compute/docs/reference/latest/instances
"""

# pylint: disable=too-few-public-methods
# pylint: disable=too-many-instance-attributes


class Instance(object):
    """Represents Instance resource."""

    def __init__(self, **kwargs):
        """Instance resource."""
        self.can_ip_forward = kwargs.get('can_ip_forward')
        self.cpu_platform = kwargs.get('cpu_platform')
        self.creation_timestamp = kwargs.get('creation_timestamp')
        self.description = kwargs.get('description')
        self.disks = kwargs.get('disks')
        self.machine_type = kwargs.get('machine_type')
        self.metadata = kwargs.get('metadata')
        self.name = kwargs.get('name')
        self.network_interfaces = kwargs.get('network_interfaces')
        self.project_id = kwargs.get('project_id')
        self.resource_id = kwargs.get('id')
        self.scheduling = kwargs.get('scheduling')
        self.service_accounts = kwargs.get('service_accounts')
        self.status = kwargs.get('status')
        self.status_message = kwargs.get('status_message')
        self.tags = kwargs.get('tags')
        self.zone = kwargs.get('zone')

    # TODO: Create utility methods to reconstruct full region, target, and
    # self link.
