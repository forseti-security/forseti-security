
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

"""Rules engine for IAP policies on backend services"""
from collections import namedtuple
import itertools
import re

from google.cloud.security.common.util import log_util
from google.cloud.security.common.util import regex_util
from google.cloud.security.scanner.audit import base_rules_engine as bre
from google.cloud.security.scanner.audit import errors as audit_errors

LOGGER = log_util.get_logger(__name__)


IapRuleDef = namedtuple('IapRuleDef',
                        ['backend_service_name',
                         'allowed_alternate_services',
                         'allowed_direct_access_sources',
                         'allowed_iap_enabled',
                        ])


class IapRulesEngine(bre.BaseRulesEngine):
    """Rules engine for applying IAP policies to backend services"""

    def __init__(self, rules_file_path, snapshot_timestamp=None):
        """Initialize.

        Args:
            rules_file_path: file location of rules
        """
        super(IapRulesEngine,
              self).__init__(rules_file_path=rules_file_path)
        self.rule_book = None

    def build_rule_book(self):
        """Build IapRuleBook from the rules definition file."""
        self.rule_book = IapRuleBook(self._load_rule_definitions())

    # pylint: disable=arguments-differ
    def find_policy_violations(self, iap_resource,
                               force_rebuild=False):
        """Determine whether IAP-related settings violate rules."""
        violations = itertools.chain()
        if self.rule_book is None or force_rebuild:
            self.build_rule_book()
        resource_rules = self.rule_book.get_resource_rules()

        for rule in resource_rules:
            violations = itertools.chain(
                violations,
                rule.find_policy_violations(iap_resource))
        return violations

    def add_rules(self, rules):
        """Add rules to the rule book."""
        if self.rule_book is not None:
            self.rule_book.add_rules(rules)


class IapRuleBook(bre.BaseRuleBook):
    """The RuleBook for enforcing IAP policy on backend service resources."""

    def __init__(self, rule_defs=None):
        """Initialization.

        Args:
            rule_defs: rule definitons
        """
        super(IapRuleBook, self).__init__()
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

        resources = rule_def.get('resource')

        for resource in resources:
            resource_ids = resource.get('resource_ids')

            if not resource_ids or len(resource_ids) < 1:
                raise audit_errors.InvalidRulesSchemaError(
                    'Missing resource ids in rule {}'.format(rule_index))

            backend_service_name = regex_util.escape_and_globify(
                rule_def.get('backend_service_name'))
            allowed_alternate_services = rule_def.get(
                'allowed_alternate_services')
            allowed_direct_access_sources = regex_util.escape_and_globify(
                rule_def.get('allowed_direct_access_sources'))
            allowed_iap_enabled = rule_def.get('allowed_iap_enabled')

            rule_def_resource = IapRuleDef(
                backend_service_name=backend_service_name,
                allowed_alternate_services=allowed_alternate_services,
                allowed_direct_access_sources=allowed_direct_access_sources,
                allowed_iap_enabled=allowed_iap_enabled,
            )

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

    def find_policy_violations(self, iap_resource):
        """Find IAP policy violations in the rule book.

        Args:
            iap_resource: IapResource

        Returns:
            Returns RuleViolation named tuple
        """
        if self.rules.backend_service_name != '^.+$':
            if not re.match(self.rules.backend_service_name,
                            iap_resource.backend_service_name):
                return

        if self.rules.allowed_alternate_services != '^.+$':
            alternate_services_regex = re.compile(
                self.rules.allowed_alternate_services)
            alternate_services_violations = [
                service for service in iap_resource.alternate_services
                if alternate_services_regex.match(service)
            ]
        else:
            alternate_services_violations = []

        if self.rules.allowed_iap_enabled != '^.+$':
            iap_enabled_regex = re.compile(
                self.rules.allowed_iap_enabled)
            iap_enabled_violation = not iap_enabled_regex.match(
                iap_resource.iap_enabled)
        else:
            iap_enabled_violation = False

        if self.rules.allowed_direct_access_sources != '^.+$':
            sources_regex = re.compile(self.rules.\
                                       allowed_direct_access_sources)
            direct_access_sources_violations = [
                source for source in iap_resource.direct_access_sources
                if sources_regex.match(source)
            ]
        else:
            direct_access_sources_violations = []

        should_raise_violation = (
            alternate_services_violations or
            iap_enabled_violation or
            direct_access_sources_violations)

        if should_raise_violation:
            yield self.RuleViolation(
                resource_type='project',
                resource_id=iap_resource.project_id,
                rule_name=self.rule_name,
                rule_index=self.rule_index,
                violation_type='IAP_VIOLATION',
                backend_service_name=iap_resource.backend_service_name,
                alternate_services_violations=alternate_services_violations,
                iap_enabled_violation=iap_enabled_violation,
                direct_access_sources_violations=(
                    direct_access_sources_violations))

    RuleViolation = namedtuple(
        'RuleViolation',
        ['resource_type', 'resource_id', 'rule_name',
         'rule_index', 'violation_type',
         'backend_service_name', 'alternate_services_violations',
         'iap_enabled_violation', 'direct_access_sources_violations'])
