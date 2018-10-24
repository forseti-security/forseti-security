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

import json
import netaddr

from google.cloud.forseti.common.util import logger
from google.cloud.forseti.common.util import parser
from google.cloud.forseti.common.util import string_formats

LOGGER = logger.get_logger(__name__)

# pylint: disable=too-many-instance-attributes

ALL_REPRESENTATIONS = ('all', '0-65355', '1-65535')
ALLOWED_RULE_ITEMS = frozenset(('allowed', 'denied', 'description', 'direction',
                                'name', 'network', 'priority', 'sourceRanges',
                                'destinationRanges', 'sourceTags',
                                'targetTags', 'sourceServiceAccounts',
                                'targetServiceAccounts'))


class Error(Exception):
    """Base error class for the module."""


class InvalidFirewallRuleError(Error):
    """Raised if a firewall rule doesn't look like a firewall rule should."""


class InvalidFirewallActionError(Error):
    """Raised if a firewall action doesn't look like a firewall rule should."""


class FirewallRule(object):
    """Represents Firewall resource."""

    def __init__(self, validate=False, **kwargs):
        """Firewall resource.

        Args:
          validate (bool): Whether to validate this rule.
          kwargs (dict): Object properties

        Raises:
          InvalidFirewallRuleError: If allowed and denied rules aren't valid.
        """
        self.project_id = kwargs.get('project_id')
        self.resource_id = kwargs.get('id')
        self.create_time = kwargs.get('firewall_rule_create_time')
        self.name = kwargs.get('firewall_rule_name')
        self.full_name = kwargs.get(
            'firewall_rule_full_name', '')
        self.kind = kwargs.get('firewall_rule_kind')
        self.network = kwargs.get('firewall_rule_network')
        self._priority = kwargs.get('firewall_rule_priority')
        self.direction = kwargs.get('firewall_rule_direction', 'INGRESS')
        if self.direction:
            self.direction = self.direction.upper()
        self._source_ranges = frozenset(parser.json_unstringify(
            kwargs.get('firewall_rule_source_ranges'), default=list()))
        self._destination_ranges = frozenset(parser.json_unstringify(
            kwargs.get('firewall_rule_destination_ranges'), default=list()))
        self._source_tags = frozenset(parser.json_unstringify(
            kwargs.get('firewall_rule_source_tags'), default=list()))
        self._target_tags = frozenset(parser.json_unstringify(
            kwargs.get('firewall_rule_target_tags'), default=list()))
        self._source_service_accounts = frozenset(parser.json_unstringify(
            kwargs.get('firewall_rule_source_service_accounts'),
            default=list()))
        self._target_service_accounts = frozenset(parser.json_unstringify(
            kwargs.get('firewall_rule_target_service_accounts'),
            default=list()))
        self.allowed = parser.json_unstringify(
            kwargs.get('firewall_rule_allowed'))
        self.denied = parser.json_unstringify(
            kwargs.get('firewall_rule_denied'))
        if self.allowed and self.denied:
            raise InvalidFirewallRuleError(
                'Cannot have allowed and denied rules (%s, %s)' % (
                    self.allowed, self.denied))
        if self.allowed is None and self.denied is None:
            raise InvalidFirewallRuleError('Must have allowed or denied rules')
        self._firewall_action = None
        if validate:
            self.validate()

    def __str__(self):
        """String representation.

        Returns:
          str: A string representation of FirewallRule.
        """
        string = ('FirewallRule('
                  'project_id=%s\n'
                  'name=%s\n'
                  'network=%s\n'
                  'priority=%s\n'
                  'direction=%s\n'
                  'action=%s\n') % (self.project_id,
                                    self.name,
                                    self.network,
                                    self._priority,
                                    self.direction,
                                    self._firewall_action)

        for field_name, value in [
                ('sourceRanges', self._source_ranges),
                ('destinationRanges', self._destination_ranges),
                ('sourceTags', self._source_tags),
                ('targetTags', self._target_tags),
                ('sourceServiceAccounts', self._source_service_accounts),
                ('targetServiceAccounts', self._target_service_accounts),
        ]:
            if value:
                string += '%s=%s\n' % (field_name, value)
        return string.strip()

    @staticmethod
    def _transform(firewall_dict, project_id=None, validate=None):
        """Transforms firewall dictionary into FirewallRule.

        Args:
          firewall_dict (dict): A dictionary with firewall field names matching
            the API field names.
          project_id (str): A project id string.
          validate (bool): Whether to validate this FirewallRule or not.

        Returns:
          FirewallRule: A FirewallRule created from the input dictionary.
        """
        if firewall_dict.get('creationTimestamp'):
            # When we are creating firewall rule gcp objects from the firewall
            # rules we defined in the firewall_rules.yaml file, the creation
            # timestamp is not part of the rule in the yaml file and if the
            # creation timestamp does not exist, we shouldn't call the parse
            # function with the empty field.
            creation_time = parser.format_timestamp(
                parser.json_stringify(
                    firewall_dict.get('creationTimestamp')),
                string_formats.TIMESTAMP_MYSQL_DATETIME_FORMAT)
        else:
            creation_time = None

        in_dict = {
            'firewall_rule_id': firewall_dict.get('id'),
            'firewall_rule_name': firewall_dict.get('name'),
            'firewall_rule_full_name':
                firewall_dict.get('full_name'),
            'firewall_rule_description': firewall_dict.get('description'),
            'firewall_rule_kind': firewall_dict.get('kind'),
            'firewall_rule_network': firewall_dict.get('network'),
            'firewall_rule_priority': firewall_dict.get('priority'),
            'firewall_rule_direction': firewall_dict.get('direction'),
            'firewall_rule_source_ranges': parser.json_stringify(
                firewall_dict.get('sourceRanges') or
                firewall_dict.get('sourceRange')),
            'firewall_rule_destination_ranges': parser.json_stringify(
                firewall_dict.get('destinationRanges') or
                firewall_dict.get('destinationRange')),
            'firewall_rule_source_tags': parser.json_stringify(
                firewall_dict.get('sourceTags') or
                firewall_dict.get('sourceTag')),
            'firewall_rule_target_tags': parser.json_stringify(
                firewall_dict.get('targetTags') or
                firewall_dict.get('targetTag')),
            'firewall_rule_source_service_accounts': parser.json_stringify(
                firewall_dict.get('sourceServiceAccounts') or
                firewall_dict.get('sourceServiceAccount')),
            'firewall_rule_target_service_accounts': parser.json_stringify(
                firewall_dict.get('targetServiceAccounts') or
                firewall_dict.get('targetServiceAccount')),
            'firewall_rule_allowed': parser.json_stringify(
                firewall_dict.get('allowed')),
            'firewall_rule_denied': parser.json_stringify(
                firewall_dict.get('denied')),
            'firewall_rule_self_link': parser.json_stringify(
                firewall_dict.get('selfLink')),
            'firewall_rule_create_time': creation_time,
        }
        if project_id:
            in_dict['project_id'] = project_id
        return FirewallRule(validate=validate, **in_dict)

    @classmethod
    def from_json(cls, json_string, project_id=None):
        """Creates a validated FirewallRule from a valid firewall JSON.

        Args:
          json_string (str): A valid firewall JSON string.
          project_id (str): A string project id.

        Returns:
          FirewallRule: A validated FirewallRule from the JSON string.

        Raises:
          InvalidFirewallRuleError: If the firewall rule is invalid.
          InvalidFirewallActionError: If the firewall action is invalid.
        """
        json_dict = json.loads(json_string)
        return FirewallRule._transform(
            json_dict, project_id=project_id, validate=True)

    @classmethod
    def from_dict(cls, firewall_dict, project_id=None, validate=False):
        """Creates an unvalidated FirewallRule from a dictionary.

        Args:
          firewall_dict (dict): A dict with firewall keys and values.
          project_id (str): A string project id.
          validate (bool): Whether to validate this rule or not.

        Returns:
          FirewallRule: A validated FirewallRule from the JSON string.

        Raises:
          InvalidFirewallRuleError: If the firewall rule is invalid.
          InvalidFirewallActionError: If the firewall action is invalid.
        """
        return FirewallRule._transform(
            firewall_dict, project_id=project_id, validate=validate)

    def as_json(self):
        """Returns a valid JSON representation of this firewall rule.

        This rule must be valid to return the representation.

        Returns:
          str: A string JSON dump of the firewall rule.

        Raises:
          InvalidFirewallRuleError: If the firewall rule is invalid.
          InvalidFirewallActionError: If the firewall action is invalid.
        """
        self.validate()
        firewall_dict = {
            'direction': self.direction,
            'network': self.network,
            'name': self.name,
        }
        for key, value in [
                self.firewall_action.json_dict(),
                ('sourceRanges', self.source_ranges),
                ('sourceTags', self.source_tags),
                ('targetTags', self.target_tags),
                ('destinationRanges', self.destination_ranges),
                ('priority', self._priority),
                ('sourceServiceAccounts', self.source_service_accounts),
                ('targetServiceAccounts', self.target_service_accounts)
        ]:
            if value:
                firewall_dict[key] = value
        return json.dumps(firewall_dict, sort_keys=True)

    def validate(self):
        """Validates that a rule is valid.

        Validation is based on reference:
        https://cloud.google.com/compute/docs/reference/beta/firewalls and
        https://cloud.google.com/compute/docs/vpc/firewalls#gcp_firewall_rule_summary_table

        Returns:
          bool: If rule is valid.

        Raises:
          InvalidFirewallRuleError: One or more rules failed validation.
        """
        self._validate_keys()
        self._validate_direction()
        self._validate_priority()
        if not self.firewall_action:
            raise InvalidFirewallRuleError('Rule missing action "%s"' % self)
        else:
            self.firewall_action.validate()

        # TODO: Verify rule name matches regex of allowed
        # names from reference

        return True

    def _validate_keys(self):
        """Checks that required keys and value restrictions.

        Required fields: name and network
        Length restrictions:
          * name <= 63 characters
          * <= 256 values:
            sourceRanges, sourceTags, targetTags, destinationRanges

        Raises:
          InvalidFirewallRuleError: If keys don't meet requirements.
        """
        if not self.name:
            raise InvalidFirewallRuleError(
                'Rule missing required field "%s"' % 'name')
        if not self.network:
            raise InvalidFirewallRuleError(
                'Rule missing required field "%s"' % 'network')

        if len(self.name) > 63:
            raise InvalidFirewallRuleError(
                'Rule name exceeds length limit of 63 chars: "%s".' %
                self.name)

        max_256_value_keys = [
            ('sourceRanges', self._source_ranges),
            ('sourceTags', self._source_tags),
            ('targetTags', self._target_tags),
            ('destinationRanges', self._destination_ranges)
        ]
        for key, value in max_256_value_keys:
            if value and len(value) > 256:
                raise InvalidFirewallRuleError(
                    'Rule entry "%s" must contain 256 or fewer values: "%s".'
                    % (key, value))

        if self._source_tags:
            if self._source_service_accounts or self._target_service_accounts:
                raise InvalidFirewallRuleError(
                    'sourceTags cannot be set when source/targetServiceAccounts'
                    ' are set')

        if self._target_tags:
            if self._source_service_accounts or self._target_service_accounts:
                raise InvalidFirewallRuleError(
                    'targetTags cannot be set when source/targetServiceAccounts'
                    ' are set')

        max_1_value_keys = [
            ('sourceServiceAccount', self.source_service_accounts),
            ('targetServiceAccount', self.target_service_accounts),
        ]
        for key, value in max_1_value_keys:
            if value and len(value) > 1:
                raise InvalidFirewallRuleError(
                    'Rule entry "%s" may contain at most 1 value: "%s".'
                    % (key, value))

    def _validate_direction(self):
        """Checks that the direction and associated fields are valid.

        Raises:
          InvalidFirewallRuleError: If:
            * Direction is 'ingress' and
              * there are no source ranges or tags
              * _destination_ranges is not set
            * Direction is 'egress' and
              * there are no source ranges or tags
              * _destination_ranges is set
        """
        if self.direction == 'INGRESS':
            if (not self._source_ranges and
                    not self._source_tags and
                    not self.source_service_accounts):
                raise InvalidFirewallRuleError(
                    'Ingress rule missing required field oneof "sourceRanges" '
                    'or "sourceTags" or "sourceServiceAccounts": "%s".' % self)

            if self._destination_ranges:
                raise InvalidFirewallRuleError(
                    'Ingress rules cannot include "destinationRanges": "%s".'
                    % self)

        elif self.direction == 'EGRESS':
            if not self._destination_ranges:
                raise InvalidFirewallRuleError(
                    'Egress rule missing required field "destinationRanges":'
                    '"%s".' % self)

            if (self._source_ranges or
                    self._source_tags or
                    self._source_service_accounts):
                raise InvalidFirewallRuleError(
                    'Egress rules cannot include "sourceRanges", "sourceTags"'
                    ' or "sourceServiceAccounts": "%s".' % self)

        else:
            raise InvalidFirewallRuleError(
                'Rule "direction" must be either "ingress" or "egress": "%s".'
                % self)

    def _validate_priority(self):
        """Checks that the priority of the rule is a valid value.

        Raises:
          InvalidFirewallRuleError: If the priority can't be converted to an int
            or if it is outside the allowed range.
        """
        if self._priority:
            try:
                priority = int(self._priority)
            except ValueError as err:
                raise InvalidFirewallRuleError(
                    'Rule "priority" could not be converted to an integer: '
                    '"%s".' % err)
            if priority < 0 or priority > 65535:
                raise InvalidFirewallRuleError(
                    'Rule "priority" out of range 0-65535: "%s".' % priority)

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
    def source_service_accounts(self):
        """The sorted source tags for this policy.

        Returns:
          list: Sorted source tags.
        """
        return sorted(self._source_service_accounts)

    @property
    def target_service_accounts(self):
        """The sorted target tags for this policy.

        Returns:
          list: Sorted target tags.
        """
        return sorted(self._target_service_accounts)

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
            if self.allowed:
                self._firewall_action = FirewallAction(
                    firewall_rules=self.allowed)
            else:
                self._firewall_action = FirewallAction(
                    firewall_rules=self.denied,
                    firewall_rule_action='denied')
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
        LOGGER.debug('Checking %s < %s', self, other)
        direction = (self.direction == other.direction or
                     self.direction is None or
                     other.direction is None)
        network = (self.network == other.network or
                   other.network is None)
        source_tags = (set(self.source_tags).issubset(other.source_tags) or not
                       other.source_tags)
        target_tags = (set(self.target_tags).issubset(other.target_tags) or not
                       other.target_tags)
        firewall_action = self.firewall_action < other.firewall_action
        source_ranges = ips_in_list(self.source_ranges, other.source_ranges)
        destination_ranges = ips_in_list(self.destination_ranges,
                                         other.destination_ranges)

        result = (direction and
                  network and
                  source_tags and
                  target_tags and
                  firewall_action and
                  source_ranges and
                  destination_ranges)
        return result

    def __gt__(self, other):
        """Test whether this policy contains the other policy.

        Checks if this rule is a superset of the allowed/denied ports and
        protocols that are in the other rule.

        Args:
          other(FirewallRule): object to compare to

        Returns:
          bool: comparison result
        """
        LOGGER.debug('Checking %s > %s', self, other)
        direction = (self.direction is None or
                     other.direction is None or
                     self.direction == other.direction)
        network = (self.network is None or
                   other.network is None or
                   self.network == other.network)
        source_tags = (set(other.source_tags).issubset(self.source_tags) or not
                       self.source_tags)
        target_tags = (set(other.target_tags).issubset(self.target_tags) or not
                       self.target_tags)
        firewall_action = self.firewall_action > other.firewall_action
        source_ranges = ips_in_list(other.source_ranges, self.source_ranges)
        destination_ranges = ips_in_list(other.destination_ranges,
                                         self.destination_ranges)
        result = (direction and
                  network and
                  source_tags and
                  target_tags and
                  firewall_action and
                  source_ranges and
                  destination_ranges)
        return result

    def __eq__(self, other):
        """Test whether this policy is the same as the other policy.

        Args:
          other(FirewallRule): object to compare to

        Returns:
          bool: comparison result
        """
        LOGGER.debug('Checking %s == %s', self, other)
        direction = self.direction == other.direction
        network = self.network == other.network
        source_tags = self._source_tags == other._source_tags
        target_tags = self._target_tags == other._target_tags
        source_ranges = self.source_ranges == other.source_ranges
        destination_ranges = self.destination_ranges == other.destination_ranges
        firewall_action = self.firewall_action == other.firewall_action
        result = (direction and
                  network and
                  source_tags and
                  target_tags and
                  source_ranges and
                  destination_ranges and
                  firewall_action)
        return result

    def is_equivalent(self, other):
        """Test whether this policy is equivalent to the other policy.

        Args:
          other(FirewallRule): object to compare to

        Returns:
          bool: comparison result
        """
        direction = self.direction == other.direction
        network = self.network == other.network
        source_tags = self._source_tags == other._source_tags
        target_tags = self._target_tags == other._target_tags
        source_ranges = self.source_ranges == other.source_ranges
        destination_ranges = self.destination_ranges == other.destination_ranges
        firewall_action = (
            self.firewall_action.is_equivalent(other.firewall_action))
        result = (direction and
                  network and
                  source_tags and
                  target_tags and
                  source_ranges and
                  destination_ranges and
                  firewall_action)
        return result


class FirewallAction(object):
    """An association of allowed or denied ports and protocols."""

    VALID_ACTIONS = frozenset(['allowed', 'denied'])
    MATCH_ANY = '*'

    def __init__(self, firewall_rules=None, firewall_rule_action='allowed'):
        """Initialize.

        Args:
          firewall_rules (list): A list of dictionaries of allowed ports
            and protocols.
          firewall_rule_action (str): The action, either allow or deny.

        Raises:
          InvalidFirewallActionError: If there are both allow and deny rules.
        """
        if firewall_rule_action not in self.VALID_ACTIONS:
            raise InvalidFirewallActionError(
                'Firewall rule action must be either allowed or denied'
                ' got: %s' % firewall_rule_action)
        self.action = firewall_rule_action
        self._any_value = None
        if firewall_rules:
            assert isinstance(firewall_rules, list)
            self.rules = sort_rules(firewall_rules)
        else:
            self.rules = []

        self._applies_to_all = None

        self._expanded_rules = None

    def __str__(self):
        """String representation.

        Returns:
          str: A string representation of FirewallAction.
        """
        return 'FirewallAction(action=%s, rules=%s)' % (self.action, self.rules)

    def json_dict(self):
        """Gets the JSON key and values for the firewall action.

        Returns:
          tuple: Of key ('allowed' or 'denied') and the firewall rules.

        Raises:
          InvalidFirewallActionError: If a rule is not formatted for the API.
        """
        self.validate()
        return self.action, self.rules

    def validate(self):
        """Validates that the firewall rules are valid for use in the API.

        Raises:
          InvalidFirewallActionError: If a rule is not formatted for the API.
        """
        for rule in self.rules:
            if 'IPProtocol' not in rule:
                raise InvalidFirewallActionError(
                    'Action must have field IPProtocol')
            if 'ports' in rule:
                if rule['IPProtocol'] not in ['tcp', 'udp']:
                    raise InvalidFirewallActionError(
                        'Only "tcp" and "udp" can have ports specified: %s' %
                        rule)
                for port in rule['ports']:
                    if '-' in port:
                        validate_port_range(port)
                    else:
                        validate_port(port)
            invalid_keys = set(rule.keys()) - {'IPProtocol', 'ports'}
            if invalid_keys:
                raise InvalidFirewallActionError(
                    'Action can only have "IPProtocol" and "ports": %s' %
                    invalid_keys)

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
    def any_value(self):
        """Returns whether this rule matches any value.

        Returns:
          bool: Whether this rule matches any value.
        """
        if self._any_value is None:
            self._any_value = all(rule == self.MATCH_ANY for rule in self.rules)
        return self._any_value

    @property
    def expanded_rules(self):
        """Returns an expanded set of ports.

        Returns:
          dict: A dict of protocol to all port numbers.
        """
        if self._expanded_rules is None:
            self._expanded_rules = {}
            if not self.any_value:
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
                (self.any_value or other.any_value or
                 self.expanded_rules.keys() == other.expanded_rules.keys() and
                 all([
                     self.ports_are_equal(
                         self.expanded_rules.get(protocol, []),
                         other.expanded_rules.get(protocol, []))
                     for protocol in self.expanded_rules
                 ])))

    def __lt__(self, other):
        """Less than.

        Args:
          other (FirewallAction): The FirewallAction to compare to.

        Returns:
          bool: Whether this action is a subset of the other action.
        """
        return (self.action == other.action and
                (self.any_value or
                 other.any_value or
                 other.applies_to_all or not
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
                (self.any_value or
                 other.any_value or
                 self.applies_to_all or not
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
    if FirewallAction.MATCH_ANY in rules:
        return rules
    for rule in sorted(rules, key=lambda k: k.get('IPProtocol', '')):
        if 'ports' in rule:
            # If the ports contains 'all', don't care about the other ports
            # or sorting. Otherwise, sort ports numerically, and handle ranges
            # through sorting by start port.
            if 'all' in rule['ports']:
                rule['ports'] = 'all'
            else:
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
        if not any([ip_in_range(ip_addr, addr) for addr in ips_list]):
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


def validate_port(port):
    """Validates that a string is a valid port number.

    Args:
      port (str): A port number string.

    Returns:
      int: The integer port number.

    Raises:
      InvalidFirewallActionError: If the port string isn't a valid port.
    """
    try:
        iport = int(port)
    except ValueError:
        raise InvalidFirewallActionError(
            'Port not a valid int: %s' % port)
    if iport < 0:
        raise InvalidFirewallActionError(
            'Port must be >= 0: %s' % port)
    if iport > 65535:
        raise InvalidFirewallActionError(
            'Port must be <= 65535: %s' % port)
    return iport


def validate_port_range(port_range):
    """Validates that a string is a valid port number.

    Args:
      port_range (str): A port range string.

    Raises:
      InvalidFirewallActionError: If the port range isn't a valid range.
    """
    split_ports = port_range.split('-')
    if len(split_ports) > 2:
        raise InvalidFirewallActionError(
            'Invalid port range: %s' % port_range)
    start = validate_port(split_ports[0])
    end = validate_port(split_ports[1])
    if start > end:
        raise InvalidFirewallActionError(
            'Start port range > end port range: %s' % port_range)
