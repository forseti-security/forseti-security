
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

from google.cloud.security.common.data_access import instance_dao
# pylint: disable=line-too-long
from google.cloud.security.common.gcp_type import instance_network_interface as ini
# pylint: enable=line-too-long
from google.cloud.security.common.util import log_util
from google.cloud.security.scanner.audit import base_rules_engine as bre
from google.cloud.security.scanner.audit import errors as audit_errors

LOGGER = log_util.get_logger(__name__)

#TODO PATH TO JSON

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


class InstanceNetworkInterfaceRulesEngine(bre.BaseRulesEngine):
    """Rules engine for InstanceNetworkInterfaceRules"""

    def __init__(self, rules_file_path):
        """Initialize.

        Args:
            rules_file_path: file location of rules
        """
        super(InstanceNetworkInterfaceRulesEngine,
              self).__init__(rules_file_path=rules_file_path)
        self.rule_book = None

    def build_rule_book(self):
        """Build InstaceNetworkInterfaceRuleBook from the rules definition file."""
        self.rule_book = InstaceNetworkInterfaceRuleBook(self._load_rule_definitions())

    # pylint: disable=arguments-differ
    def find_policy_violations(self, instance_network_interface,
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
                                         find_violations(instance_network_interface))
        return violations

    def add_rules(self, rules):
        """Add rules to the rule book."""
        if self.rule_book is not None:
            self.rule_book.add_rules(rules)


class InstaceNetworkInterfaceRuleBook(bre.BaseRuleBook):
    """The RuleBook for enforced networks resources."""

    def __init__(self,
                 rule_defs=None):
        """Initialize.

        Args:
            rule_defs: The parsed dictionary of rules from the YAML
                definition file.
            snapshot_timestamp: The snapshot to lookup data.
        """
        super(InstaceNetworkInterfaceRuleBook, self).__init__()
        self.resource_rules_map = {}
        if not rule_defs:
            self.rule_defs = {}
        else:
            self.rule_defs = rule_defs
            self.add_rules(rule_defs)

    def add_rules(self, rule_defs):
        """Add rules to the rule book"""
        print(rule_defs)
        for (i, rule) in enumerate(rule_defs.get('rules', [])):
            self.add_rule(rule, i)

    def add_rule(self, rule_def, rule_index):
        """Add a rule to the rule book.
        Add a rule to the rule book.

        The rule supplied to this method is the dictionary parsed from
        the rules definition file.

        For example, this rule...

            # rules yaml:
            rules:
              - project: a rule
                network: whitelist
                is_externam
                whitelist:
                  - project:network

        ... gets parsed into:

            {
                'name': 'a rule',
                'resource': {
                    'project': '',
                    'network': self,
                    'is_external': boolean 
                }
                whitelist {
                    'network': 'project'...
    
                }
            }

        Args:
            rule_def: A dictionary containing rule definition properties.
            rule_index: The index of the rule from the rule definitions.
                Assigned automatically when the rule book is built.

        Args:
            rule_def: A dictionary containing rule definition properties.
            rule_index: The index of the rule from the rule definitions.
            Assigned automatically when the rule book is built.
        """
        project = rule_def.get('project')
        network = rule_def.get('network')
        whitelist = rule_def.get('whitelist')
        is_external_network = rule_def.get('is_external_network')

        if (whitelist is None) or (project is None) or (network is None) or\
               (is_external_network is None):
                raise audit_errors.InvalidRulesSchemaError(
                    'Faulty rule {}'.format(rule_def.get('name')))

        rule_def_resource = { 'whitelist' : whitelist,
                              'project': escape_and_globify(project),
                              'network': escape_and_globify(network),
                              'is_external_network': is_external_network}

        rule = Rule(rule_name=rule_def.get('name'),
                    rule_index=rule_index,
                    rules=rule_def_resource)

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

        resource_rules = []

class Rule(object):
    def __init__(self, rule_name, rule_index, rules):
        """Initialize.

        Args:
            rule_name: Name of the loaded rule
            rule_index: The index of the rule from the  definitions
            rules: the network instance 
            the resources to accosiate with the rules (so far every network_instance)
        """
        self.rule_name = rule_name
        self.rule_index = rule_index
        self.rules = rules


    def find_violations(self, instance_network_interface):
        """
        raise violation is the ip is not in the whitelist
        Args:
                instance_network_interface: InstanceNetworkInterface obj
        """
        network_and_project = re.search('compute\/v1\/projects\/([^\/]*).*networks\/([^\/]*)', instance_network_interface.network)
        project = network_and_project.group(1)
        network = network_and_project.group(2)
        is_external_network = instance_network_interface.accessConfigs is not None
        if not self.rules['whitelist'].get(project):
            if is_external_network:
                yield self.RuleViolation(
                    resource_type='instance',
                    rule_name=self.rule_name,
                    rule_index=self.rule_index,
                    violation_type='UNENFORCED_NETWORK_VIOLATION',
                    project=project,
                    network=network,
                    ips='project_not_covered')

        elif network not in self.rules['whitelist'].get(project) and is_external_network:
            yield self.RuleViolation(
                resource_type='instance',
                rule_name=self.rule_name,
                rule_index=self.rule_index,
                violation_type='UNENFORCED_NETWORK_VIOLATION',
                project=project,
                network=network,
                ips=instance_network_interface.accessConfigs[0].get('natIP'))

    # Rule violation.
    # resource_type: string
    # rule_name: string
    # rule_index: int
    # violation_type: UNENFORCED_NETWORK_VIOLATION
    # project: string
    # network: string
    # ip: string
    RuleViolation = namedtuple('RuleViolation',
                            ['resource_type', 'rule_name',
                            'rule_index', 'violation_type', 'project',
                            'network', 'ips'])
