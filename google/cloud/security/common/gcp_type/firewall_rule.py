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

import netaddr

from google.cloud.security.common.util import parser

# pylint: disable=too-many-instance-attributes

ALL_REPRESENTATIONS = ('all', '0-65355', '1-65535')


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
        self._source_ranges = frozenset(parser.json_unstringify(
            kwargs.get('firewall_rule_source_ranges', '[]')))
        self._destination_ranges = frozenset(parser.json_unstringify(
            kwargs.get('firewall_rule_destination_ranges', '[]')))
        self._source_tags = frozenset(parser.json_unstringify(
            kwargs.get('firewall_rule_source_tags', '[]')))
        self._target_tags = frozenset(parser.json_unstringify(
            kwargs.get('firewall_rule_target_tags', '[]')))
        self.allowed = parser.json_unstringify(
            kwargs.get('firewall_rule_allowed', '[]'))
        self.denied = parser.json_unstringify(
            kwargs.get('firewall_rule_denied', '[]'))
        self._action = kwargs.get('firewall_rule_action', 'allow')
        self._firewall_action = None

    @property
    def source_ranges(self):
        """The sorted source ranges for this policy.

        Returns:
          list: Sorted source ips ranges.
        """
        return sorted(self._source_ranges)

    @property
    def destination_ranges(self):
        """The sorted destination ranges for this policy.

        Returns:
          list: Sorted destination ips ranges.
        """
        return sorted(self._destination_ranges)

    @property
    def source_tags(self):
        """The sorted source tags for this policy.

        Returns:
          list: Sorted source tags.
        """
        return sorted(self._source_tags)

    @property
    def target_tags(self):
        """The sorted target tags for this policy.

        Returns:
          list: Sorted target tags.
        """
        return sorted(self._target_tags)

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

    @property
    def firewall_action(self):
        """The protocols and ports allowed or denied by this policy.

        https://cloud.google.com/compute/docs/reference/beta/firewalls

        Returns:
          FirewallAction: An object that represents what ports and protocols are
            allowed or denied.

        Raises:
          ValueError: If there are both allow and deny actions for a rule.
        """
        if not self._firewall_action:
            action_dict = {
                'firewall_rule_allowed': self.allowed,
                'firewall_rule_denied': self.denied,
                'firewall_rule_action': self._action,
            }
            self._firewall_action = FirewallAction(**action_dict)
        return self._firewall_action

    def __lt__(self, other):
        """Test whether this policy is contained in another policy.

        Checks if this rule is a subset of the allowed/denied ports and
        protocols that are in the other rule.

        Args:
          other(FirewallRule): object to compare to

        Returns:
          bool: comparison result
        """
        return ((self.direction == other.direction or
                 self.direction is None or
                 other.direction is None) and
                (self.network == other.network or other.network is None) and
                set(self.source_tags).issubset(other.source_tags) and
                set(self.target_tags).issubset(other.target_tags) and
                self.firewall_action < other.firewall_action and
                ips_in_list(self.source_ranges, other.source_ranges) and
                ips_in_list(self.destination_ranges, other.destination_ranges))

    def __gt__(self, other):
        """Test whether this policy contains the other policy.

        Checks if this rule is a superset of the allowed/denied ports and
        protocols that are in the other rule.

        Args:
          other(FirewallRule): object to compare to

        Returns:
          bool: comparison result
        """
        return ((self.direction is None or
                 other.direction is None or
                 self.direction == other.direction) and
                (self.network is None or self.network == other.network) and
                set(other.source_tags).issubset(self.source_tags) and
                set(other.target_tags).issubset(self.target_tags) and
                self.firewall_action > other.firewall_action and
                ips_in_list(other.source_ranges, self.source_ranges) and
                ips_in_list(other.destination_ranges, self.destination_ranges))

    # pylint: disable=protected-access
    def __eq__(self, other):
        """Test whether this policy is the same as the other policy.

        Args:
          other(FirewallRule): object to compare to

        Returns:
          bool: comparison result
        """
        return (self.direction == other.direction and
                self.network == other.network and
                self._source_tags == other._source_tags and
                self._target_tags == other._target_tags and
                self.source_ranges == other.source_ranges and
                self.destination_ranges == other.destination_ranges and
                self.firewall_action == other.firewall_action)

    # pylint: disable=protected-access
    def is_equivalent(self, other):
        """Test whether this policy is equivalent to the other policy.

        Args:
          other(FirewallRule): object to compare to

        Returns:
          bool: comparison result
        """
        return (self.direction == other.direction and
                self.network == other.network and
                self._source_tags == other._source_tags and
                self._target_tags == other._target_tags and
                self.source_ranges == other.source_ranges and
                self.destination_ranges == other.destination_ranges and
                self.firewall_action.is_equivalent(other.firewall_action))


class FirewallAction(object):
    """An association of allowed or denied ports and protocols."""

    def __init__(self, firewall_rule_allowed=None, firewall_rule_denied=None,
                 firewall_rule_action='allow'):
        """Initialize.

        Args:
          firewall_rule_allowed (list): A list of dictionaries of allowed ports
            and protocols.
          firewall_rule_denied (list): A list of dictionaries of denied ports
            and protocols.
          firewall_rule_action (str): The action, either allow or deny.

        Raises:
          ValueError: If there are both allow and deny rules.
        """
        if firewall_rule_allowed:
            if firewall_rule_denied:
                raise ValueError(
                    'Rule cannot have deny (%s) and allow (%s) actions' %
                    (firewall_rule_denied, firewall_rule_allowed))
            self.action = 'allow'
            self.rules = sort_rules(firewall_rule_allowed)
        elif firewall_rule_denied:
            self.action = 'deny'
            self.rules = sort_rules(firewall_rule_denied)
        else:
            self.action = firewall_rule_action
            self.rules = []

        self._applies_to_all = None

        self._expanded_rules = {}

    @property
    def applies_to_all(self):
        """Returns whether this applies to all ports and protocols or not.

        Returns:
          bool: Whether this applies to all ports and protocols or not.
        """
        if self._applies_to_all is None:
            self._applies_to_all = False
            for rule in self.rules:
                protocol = rule.get('IPProtocol')
                if protocol == 'all':
                    self._applies_to_all = True
                    break
        return self._applies_to_all

    @property
    def expanded_rules(self):
        """Returns an expanded set of ports.

        Returns:
          list: A list of every string port number.
        """
        if not self._expanded_rules:
            self._expanded_rules = {}
            for rule in self.rules:
                protocol = rule.get('IPProtocol')
                ports = rule.get('ports', ['all'])
                expanded_ports = set(expand_ports(ports))
                current_ports = self._expanded_rules.get(protocol, set([]))
                current_ports.update(expanded_ports)
                self._expanded_rules[protocol] = current_ports
        return self._expanded_rules

    @staticmethod
    def ports_are_subset(ports_1, ports_2):
        """Returns whether one port list is a subset of another.

        Args:
          ports_1 (list): A list of string port numbers.
          ports_2 (list): A list of string port numbers.

        Returns:
          bool: Whether ports_1 are a subset of ports_2 or not.
        """
        if any([a in ports_2 for a in ALL_REPRESENTATIONS]):
            return True
        return set(ports_1).issubset(ports_2)

    @staticmethod
    def ports_are_equal(ports_1, ports_2):
        """Returns whether two port lists are the same.

        Args:
          ports_1 (list): A list of string port numbers.
          ports_2 (list): A list of string port numbers.

        Returns:
          bool: Whether ports_1 have the same ports as ports_2.
        """
        if (any([a in ports_1 for a in ALL_REPRESENTATIONS]) and
                any([a in ports_2 for a in ALL_REPRESENTATIONS])):
            return True
        return set(ports_1) == set(ports_2)

    def is_equivalent(self, other):
        """Returns whether this action and another are functionally equivalent.

        Args:
          other (FirewallAction): Another FirewallAction.

        Returns:
          bool: Whether these two FirewallActions are functionally equivalent.
        """
        return (self.action == other.action and
                self.expanded_rules.keys() == other.expanded_rules.keys() and
                all([
                    self.ports_are_equal(
                        self.expanded_rules.get(protocol, []),
                        other.expanded_rules.get(protocol, []))
                    for protocol in self.expanded_rules
                ]))

    def __lt__(self, other):
        """Less than.

        Args:
          other (FirewallAction): The FirewallAction to compare to.

        Returns:
          bool: Whether this action is a subset of the other action.
        """
        return (self.action == other.action and
                (other.applies_to_all or not
                 other.expanded_rules or
                 all([
                     self.ports_are_subset(
                         self.expanded_rules.get(protocol, []),
                         other.expanded_rules.get(protocol, []))
                     for protocol in self.expanded_rules])))

    def __gt__(self, other):
        """Greater than.

        Args:
          other (FirewallAction): The FirewallAction to compare to.

        Returns:
          bool: Whether this action is a superset of the other action.
        """
        return (self.action == other.action and
                (self.applies_to_all or not
                 self.expanded_rules or
                 all([
                     self.ports_are_subset(
                         other.expanded_rules.get(protocol, []),
                         self.expanded_rules.get(protocol, []))
                     for protocol in other.expanded_rules])))

    def __eq__(self, other):
        """Equals.

        Args:
          other (FirewallAction): The FirewallAction to compare to.

        Returns:
          bool: If this action is the exact same as the other FirewallAction.
        """
        return self.action == other.action and self.rules == other.rules

def sort_rules(rules):
    """Sorts firewall rules by protocol and sorts ports.

    Args:
      rules (list): A list of firewall rule dictionaries.

    Returns:
      list: A list of sorted firewall rules.
    """
    sorted_rules = []
    for rule in sorted(rules, key=lambda k: k.get('IPProtocol' '')):
        if 'ports' in rule:
            # Sort ports numerically handle ranges through sorting by start port
            rule['ports'] = sorted(rule['ports'],
                                   key=lambda k: int(k.split('-')[0]))
        sorted_rules.append(rule)
    return sorted_rules


def ips_in_list(ips, ips_list):
    """Checks whether the ips and ranges are all in a list.

    Examples:
      ips_in_list([1.1.1.1], [0.0.0.0/0]) = True
      ips_in_list([1.1.1.1/24], [0.0.0.0/0]) = True
      ips_in_list([1.1.1.1, 1.1.1.2], [0.0.0.0/0]) = True
      ips_in_list([1.1.1.1, 2.2.2.2], [1.1.1.0/24, 2.2.2.0/24]) = True
      ips_in_list([0.0.0.0/0], [1.1.1.1]) = False

    Args:
      ips (list): A list of string IP addresses.
      ips_list (list): A list of string IP addresses.

    Returns:
      bool: Whether the ips are all in the given ips_list.
    """
    if not ips or not ips_list:
        return True
    for ip_addr in ips:
        if not ips_list:
            return False
        if not any([ip_in_range(ip_addr, ips) for ips in ips_list]):
            return False
    return True

def ip_in_range(ip_addr, ip_range):
    """Checks whether the ip/ip range is in another ip range.

    Examples:
      ip_in_range(1.1.1.1, 0.0.0.0/0) = True
      ip_in_range(1.1.1.1/24, 0.0.0.0/0) = True
      ip_in_range(0.0.0.0/0, 1.1.1.1) = False

    Args:
      ip_addr (string): A list of string IP addresses.
      ip_range (string): A list of string IP addresses.

    Returns:
      bool: Whether the ip / ip range is in another ip range.
    """
    ip_network = netaddr.IPNetwork(ip_addr)
    ip_range_network = netaddr.IPNetwork(ip_range)
    return ip_network in ip_range_network

def expand_port_range(port_range):
    """Expands a port range.

    From https://cloud.google.com/compute/docs/reference/beta/firewalls, ports
    can be of the form "<number>-<number>".

    Args:
      port_range (string): A string of format "<number_1>-<number_2>".

    Returns:
      list: A list of string integers from number_1 to number_2.
    """
    start, end = port_range.split('-')
    return [str(i) for i in xrange(int(start), int(end) + 1)]

def expand_ports(ports):
    """Expands all ports in a list.

    From https://cloud.google.com/compute/docs/reference/beta/firewalls, ports
    can be of the form "<number" or "<number>-<number>".

    Args:
      ports (list): A list of strings of format "<number>" or
        "<number_1>-<number_2>".

    Returns:
      list: A list of all port number strings with the ranges expanded.
    """
    expanded_ports = []
    if not ports:
        return []
    for port_str in ports:
        if '-' in port_str:
            expanded_ports.extend(expand_port_range(port_str))
        else:
            expanded_ports.append(port_str)
    return expanded_ports
