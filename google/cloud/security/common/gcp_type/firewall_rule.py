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

"""A Firewall.

See: https://cloud.google.com/compute/docs/reference/latest/firewalls
"""

from google.cloud.security.common.util import parser

# pylint: disable=too-many-instance-attributes


class FirewallRule(object):
    """Represents Firewall resource."""

    def __init__(self, **kwargs):
        """Firewall resource.

        Args:
          kwargs (dict): Object properties"""
        self.project_id = kwargs.get('project_id')
        self.resource_id = kwargs.get('id')
        self.create_time = kwargs.get('firewall_rule_create_time')
        self.name = kwargs.get('firewall_rule_name')
        self.kind = kwargs.get('firewall_rule_kind')
        self.network = kwargs.get('firewall_rule_network')
        self._priority = kwargs.get('firewall_rule_priority')
        self.direction = kwargs.get('firewall_rule_direction')
        self.source_ranges = parser.json_unstringify(
            kwargs.get('firewall_rule_source_ranges'))
        self.destination_ranges = parser.json_unstringify(
            kwargs.get('firewall_rule_destination_ranges'))
        self.source_tags = parser.json_unstringify(
            kwargs.get('firewall_rule_source_tags'))
        self.target_tags = parser.json_unstringify(
            kwargs.get('firewall_rule_target_tags'))
        self.target_tags = parser.json_unstringify(
            kwargs.get('firewall_rule_target_service_accounts'))
        self.allowed = parser.json_unstringify(
            kwargs.get('firewall_rule_allowed'))
        self.denied = parser.json_unstringify(
            kwargs.get('firewall_rule_denied'))

    @property
    def priority(self):
        """The effective priority of the firewall rule.

        Per https://cloud.google.com/compute/docs/reference/latest/firewalls
        the default priority is 1000.

        Returns:
          int: Rule priority (lower is more important)
        """
        if self._priority is None:
            return 1000
        return self._priority
