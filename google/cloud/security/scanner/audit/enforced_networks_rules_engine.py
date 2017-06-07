
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

"""Rules engine for CloudSQL acls"""
from collections import namedtuple
import itertools
import re

# pylint: disable=line-too-long
from google.cloud.security.common.gcp_type import enforced_networks as en
# pylint: enable=line-too-long
from google.cloud.security.common.util import log_util
from google.cloud.security.scanner.audit import base_rules_engine as bre
from google.cloud.security.scanner.audit import errors as audit_errors

LOGGER = log_util.get_logger(__name__)

#TODO PATH TO JSON

# TODO: move this to utils since it's used in more that one engine
def escape_and_globify(pattern_string):
    """Given a pattern string with a glob, create actual regex pattern.

    To require > 0 length glob, change the "*" to ".+". This is to handle
    strings like "*@company.com". (THe actual regex would probably be
    ".*@company.com", except that we don't want to match zero-length
    usernames before the "@".)

    Args:
        pattern_string: The pattern string of which to make a regex.

    Returns:
    The pattern string, escaped except for the "*", which is
    transformed into ".+" (match on one or more characters).
    """

    return '^{}$'.format(re.escape(pattern_string).replace('\\*', '.+'))


class EnforcedNetworksRulesEngine(bre.BaseRulesEngine):
    """Rules engine for CloudSQL acls"""

    def __init__(self, rules_file_path):
        """Initialize.

        Args:
            rules_file_path: file location of rules
        """
        super(EnforcedNetworksRulesEngine,
              self).__init__(rules_file_path=rules_file_path)
        self.rule_book = None

    def build_rule_book(self):
        """Build EnforcedNetworksRuleBook from the rules definition file."""
        self.rule_book = EnforcedNetworksRuleBook(self._load_rule_definitions())

    # pylint: disable=arguments-differ
    def find_policy_violations(self, enforced_networks,
                               force_rebuild=False):
        #TODO: change the comment ot be more clear
        """Determine whether the networks violates rules."""
        violations = itertools.chain()
        if self.rule_book is None or force_rebuild:
            self.build_rule_book()
        resource_rules = self.rule_book.get_resource_rules()

        for rule in resource_rules:
            violations = itertools.chain(violations,
                                         rule.\
                                         find_policy_violations(enforced_networks))
        return violations

    def add_rules(self, rules):
        """Add rules to the rule book."""
        if self.rule_book is not None:
            self.rule_book.add_rules(rules)


class EnforcedNetworksRuleBook(bre.BaseRuleBook):
    """The RuleBook for enforced networks resources."""

    def __init__(self, rule_defs=None):
        """Initialization.

        Args:
            rule_defs: rule definitons
        """
        super(EnforcedNetworksRuleBook, self).__init__()
        self.resource_rules_map = {}
        if not rule_defs:
            self.rule_defs = {}
        else:
            self.rule_defs = rule_defs
            self.add_rules(rule_defs)

    def add_rules(self, rule_defs):
        """Add rules to the rule book"""
        for (i, rule) in enumerate(rule_defs.get('rules', [])):
            self.add_rule(rule, i)

    def add_rule(self, rule_def, rule_index):
        """Add a rule to the rule book.

        Args:
            rule_def: A dictionary containing rule definition properties.
            rule_index: The index of the rule from the rule definitions.
            Assigned automatically when the rule book is built.
        """

        project = rule_def.get('project')
        network = rule_def.get('network')
        enforced_networks = rules_def.get('enforced_networks')
         
        if (project is None) or (network is None) or (enforced_networks is None):
            raise audit_errors.InvalidRulesSchemaError('Faulty rule {}'.format(rule_def.get('name')))

#TODO make ENforcedNetworks type in gcp_type
#TODO maybe some json magic on globified stuff
        rule_def_resource = en.EnforcedNetworks(
            escape_and_globify(project),
            escape_and_globify(network),
            escape_and_globify(enforced_networks))

        rule = Rule(rule_name=rule_def.get('name'), rule_index=rule_index, rules=rule_def_resource)

        resource_rules = self.resource_rules_map.get(rule_index)

        if not resource_rules:
            self.resource_rules_map[rule_index] = rule

    def get_resource_rules(self):
        """Get all the resource rules for (resource, RuleAppliesTo.*).

        Args:
            resource: The resource to find in the ResourceRules map.

        Returns:
            A list of ResourceRules.
        """
        resource_rules = []

        for resource_rule in self.resource_rules_map:
            resource_rules.append(self.resource_rules_map[resource_rule])

        return resource_rules


class Rule(object):
    """Rule properties from the rule definition file.
    Also finds violations.
    """

    def __init__(self, rule_name, rule_index, rules):
        """Initialize.

        Args:
            rule_name: Name of the loaded rule
            rule_index: The index of the rule from the rule definitions
            rules: The rules from the file
        """
        self.rule_name = rule_name
        self.rule_index = rule_index
        self.rules = rules
#TODO rename enforced_networks_rules?
    def find_policy_violations(self, enforced_networks_rules):
        """
        enforced_networks string of the name of a network 

        """
        for rule in self.rules:
            if rule not in enforced_networks_rules:
                yield self.RuleViolation(
                    rule_name=self.rule_name,
                    rule_index=self.rule_index,
                    violation_type='UNENFORCED_NETWORK_VIOLATION',
                    project=enforced_networks_rules.project,
                    network=enforced_networks_rules.network,
                    enforced_networks=enforced_networks_rules.enforced_networks)

    # Rule violation.
    # rule_name: string
    # rule_index: int
    # violation_type: UNENFORCED_NETWORK_VIOLATION
    # project: string
    # network: string
    # enforced_networks: dict
    RuleViolation = namedtuple('RuleViolation',
                               ['rule_name', 'rule_index', 'violation_type',
                                'project', 'network', 'enforced_networks'])
