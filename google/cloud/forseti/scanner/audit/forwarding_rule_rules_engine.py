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

"""Rules engine for forwarding rules engine"""
from collections import namedtuple

from google.cloud.forseti.common.gcp_type.resource import ResourceType
from google.cloud.forseti.common.util import logger
from google.cloud.forseti.scanner.audit import base_rules_engine as bre
from google.cloud.forseti.scanner.audit import errors as audit_errors

LOGGER = logger.get_logger(__name__)


class ForwardingRuleRulesEngine(bre.BaseRulesEngine):
    """Rules engine for forwarding rules"""

    RuleViolation = namedtuple('RuleViolation',
                               ['violation_type', 'target', 'rule_index',
                                'load_balancing_scheme', 'port_range',
                                'resource_type', 'port', 'ip_protocol',
                                'ip_address', 'resource_id', 'full_name',
                                'resource_data', 'resource_name'])

    def __init__(self, rules_file_path, snapshot_timestamp=None):
        """Initialize.

        Args:
            rules_file_path (str): file location of rules
            snapshot_timestamp (str): snapshot timestamp. Defaults to None.
                If set, this will be the snapshot timestamp
                used in the engine.
        """
        super(ForwardingRuleRulesEngine, self).__init__(
            rules_file_path=rules_file_path,
            snapshot_timestamp=snapshot_timestamp)
        self.rule_book = None

    def build_rule_book(self, global_configs=None):
        """Build forwarding rules rule book from the rules definition file.

        Args:
            global_configs (dict): Global configurations.
        """
        self.rule_book = ForwardingRuleRulesBook(self._load_rule_definitions())

    def find_violations(self, forwarding_rule, force_rebuild=False):
        """Determine whether forwarding rule violates rules.

        Args:
            forwarding_rule (ForwardingRule): The one specific forwarding rule
                to be matched against all white list rules
            force_rebuild (bool): If True, rebuilds the rule book. This will
                reload the rules definition file and add the rules to the book.

        Returns:
            RuleViolation: A rule violation tuple with all data about the
            forwarding rule that didnt pass a white list
        """
        if self.rule_book is None or force_rebuild:
            self.build_rule_book()
        resource_rules = self.rule_book.get_resource_rules()

        # If there is no forwarding rules defined in the rule file then no
        # forwarding rule is violated.
        # TODO: Maybe we can move this up a level so we don't have to go
        # through the iteration process.
        if not resource_rules:
            return None

        # If your fwd rule matches at least 1 rule in rulebook return None
        # else your fwd rule violates the rulebook and will return a violation
        for rule in resource_rules:
            if rule.find_match(forwarding_rule):
                return None

        return self.RuleViolation(
            violation_type='FORWARDING_RULE_VIOLATION',
            load_balancing_scheme=(
                forwarding_rule.load_balancing_scheme),
            target=forwarding_rule.target,
            port_range=forwarding_rule.port_range,
            port=forwarding_rule.ports,
            ip_protocol=forwarding_rule.ip_protocol,
            ip_address=forwarding_rule.ip_address,
            resource_id=forwarding_rule.resource_id,
            full_name=forwarding_rule.full_name,
            rule_index=len(resource_rules),
            resource_name=forwarding_rule.name,
            resource_type=ResourceType.FORWARDING_RULE,
            resource_data=str(forwarding_rule))

    def add_rules(self, rules):
        """Add rules to the rule book.

        Args:
            rules (dict): rule from file to be added to book
        """
        if self.rule_book is not None:
            self.rule_book.add_rules(rules)


class ForwardingRuleRulesBook(bre.BaseRuleBook):
    """The RuleBook for forwarding rules resources."""

    def __init__(self, rule_defs=None):
        """Initialization.

        Args:
            rule_defs (dict): rule definitions
        """
        super(ForwardingRuleRulesBook, self).__init__()
        self.resource_rules_map = {}
        if not rule_defs:
            self.rule_defs = {}
        else:
            self.rule_defs = rule_defs
            self.add_rules(rule_defs)

    def add_rules(self, rule_defs):
        """Add rules to the rule book

        Args:
            rule_defs (dict): list of rules and their index number
        """
        for (i, rule) in enumerate(rule_defs.get('rules', [])):
            self.add_rule(rule, i)

    def add_rule(self, rule_def, rule_index):
        """Add a rule to the rule book.

        Args:
            rule_def (dict): A dictionary containing rule definition
                properties.
            rule_index (int): The index of the rule from the rule definitions.
                Assigned automatically when the rule book is built.

        Raises:
            InvalidRulesSchemaError: if rule has format error
        """
        target = rule_def.get('target')
        mode = rule_def.get('mode')
        load_balancing_scheme = rule_def.get('load_balancing_scheme')
        port_range = rule_def.get('port_range')
        port = rule_def.get('port')
        ip_address = rule_def.get('ip_address')
        ip_protocol = rule_def.get('ip_protocol')
        if ((target is None) or
                (mode is None) or
                (load_balancing_scheme is None) or
                (ip_address is None) or
                (ip_protocol is None)):
            raise audit_errors.InvalidRulesSchemaError(
                'Faulty rule {}'.format(rule_def.get('name')))
        rule_def_resource = {'target': target,
                             'mode': mode,
                             'load_balancing_scheme': load_balancing_scheme,
                             'port_range': port_range,
                             'ip_address': ip_address,
                             'ip_protocol': ip_protocol,
                             'port': port,
                             'full_name': ''}

        rule = Rule(rule_name=rule_def.get('name'),
                    rule_index=rule_index,
                    rules=rule_def_resource)

        resource_rules = self.resource_rules_map.get(rule_index)
        if not resource_rules:
            self.resource_rules_map[rule_index] = rule

    def get_resource_rules(self):
        """Get all the resource_rules as a list from the resource_rules_map

        Returns:
            list: A list of ResourceRules.
        """
        return list(self.resource_rules_map.values())


class Rule(object):
    """Rule properties from the rule definition file.
    Also finds violations.
    """

    def __init__(self, rule_name, rule_index, rules):
        """Initialize.

        Args:
            rule_name (str): Name of the loaded rule
            rule_index (int): The index of the rule from the rule definitions
            rules (dict): The rules from the file
        """
        self.rule_name = rule_name
        self.rule_index = rule_index
        self.rules = rules

    def find_match(self, forwarding_rule):
        """Find if the passed in forwarding rule matches any in the rule book

        Args:
            forwarding_rule (ForwardingRule): forwarding rule resource

        Returns:
            bool: true if the forwarding rule matched at least 1 rule in the
                rulebook
        """
        ip_matched = forwarding_rule.ip_address == self.rules['ip_address']

        scheme_matched = forwarding_rule.load_balancing_scheme == self.rules[
            'load_balancing_scheme']

        # only one of port or port range will be populated by the rule
        # for the port range. it is a string of form int-int
        # for the port, it will be the first and only port in the list
        ports_matched = False
        if self.rules['port_range'] and forwarding_rule.port_range:
            ports_matched = forwarding_rule.port_range == self.rules[
                'port_range']
        elif self.rules['port'] and len(forwarding_rule.ports) == 1:
            ports_matched = int(forwarding_rule.ports[0]) == int(
                self.rules['port'])

        protocol_matched = forwarding_rule.ip_protocol == self.rules[
            'ip_protocol']

        # Checking for matching based on layer 4 protocol
        # ESP has no ports
        # TCP and UDP does have ports
        # leaving it open for new layer 4 if need be
        # default cause is no match thus a return False
        if forwarding_rule.ip_protocol == 'ESP':
            matched = (ip_matched and
                       scheme_matched and
                       protocol_matched)
        elif forwarding_rule.ip_protocol == 'TCP' \
                or forwarding_rule.ip_protocol == 'UDP':
            matched = (ip_matched and
                       scheme_matched and
                       ports_matched and
                       protocol_matched)
        else:
            matched = False
        return matched
