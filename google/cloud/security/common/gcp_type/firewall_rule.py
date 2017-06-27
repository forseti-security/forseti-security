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

"""A Firewall.

See: https://cloud.google.com/compute/docs/reference/latest/firewalls
"""

# pylint: disable=too-few-public-methods
# pylint: disable=too-many-instance-attributes


class FirewallRule(object):
    """Represents Firewall resource."""

    def __init__(self, **kwargs):
        """Firewall resource."""
        self.project_id = kwargs.get('project_id')
        self.resource_id = kwargs.get('id')
        self.create_time = kwargs.get('firewall_rule_create_time')
        self.name = kwargs.get('firewall_rule_name')
        self.kind = kwargs.get('firewall_rule_kind')
        self.network = kwargs.get('firewall_rule_network')
        self._priority = kwargs.get('firewall_rule_priority')
        self.direction = kwargs.get('firewall_rule_direction')
        self.source_ranges = kwargs.get('firewall_rule_source_ranges')
        self.destination_ranges = kwargs.get('firewall_rule_destination_ranges')
        self.source_tags = kwargs.get('firewall_rule_source_tags')
        self.target_tags = kwargs.get('firewall_rule_target_tags')
        self.allowed = kwargs.get('firewall_rule_allowed')
        self.denied = kwargs.get('firewall_rule_denied')

    @property
    def priority(self):
        if self._priority is None:
            return 1000
        else:
            return self._priority
