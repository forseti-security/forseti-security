
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

# pylint: disable=line-too-long
from google.cloud.security.common.gcp_type import backend_service
from google.cloud.security.common.gcp_type import instance_group_manager
from google.cloud.security.common.gcp_type import instance_group
from google.cloud.security.common.gcp_type import instance
from google.cloud.security.common.gcp_type import instance_template
# pylint: enable=line-too-long
from google.cloud.security.common.util import log_util
from google.cloud.security.scanner.audit import base_rules_engine as bre
from google.cloud.security.scanner.audit import errors as audit_errors

LOGGER = log_util.get_logger(__name__)


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


IapRuleDef = collections.namedtuple('IapRuleDef',
                                    ['backend_service_name',
                                     'allowed_direct_access_networks',
                                     'allow_exposure_via_alternate_service'])


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
    def find_policy_violations(self, the_backend_service,
                               force_rebuild=False):
        """Determine whether IAP-related settings violate rules."""
        violations = itertools.chain()
        if self.rule_book is None or force_rebuild:
            self.build_rule_book()
        resource_rules = self.rule_book.get_resource_rules()

        for rule in resource_rules:
            violations = itertools.chain(violations,
                                         rule.\
                                         find_policy_violations(the_backend_service))
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

            backend_service_name = escape_and_globify(
                rule_def.get('backend_service_name'))
            allowed_direct_access_networks = escape_and_globify(
                rule_def.get('allowed_direct_access_networks'))
            allow_exposure_via_alternate_service = rule_def.get(
                'allow_exposure_via_alternate_service')

            rule_def_resource = IapRuleDef(
                backend_service_name=escape_and_globify(instance_name),
                authorized_networks=escape_and_globify(authorized_networks),
                allow_exposure_via_alternate_service=(
                    allow_exposure_via_alternate_service),
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

    def find_policy_violations(self, the_backend_service):
        """Find IAP policy violations in the rule book.

        Args:
            the_backend_service: BackendService resource

        Returns:
            Returns RuleViolation named tuple
        """
        filter_list = []
        if self.rules.backend_service_name != '^.+$':
            bs_name_bool = re.match(self.rules.backend_service_name,
                                    the_backend_service.name)
        else:
            bs_name_bool = True

        if self.rules.allowed_direct_access_networks != '^.+$':
            networks_regex = re.compile(self.rules.\
                                        allowed_direct_access_networks)
            filter_list = [
                net for net in cloudsql_acl.authorized_networks if\
                authorized_networks_regex.match(net)
            ]

            allowed_direct_networks_bool = bool(filter_list)
        else:
            allowed_direct_networks_bool = True

        if not self.rules.allow_exposure_via_alternate_service:
            exposed_via_alternate_services_bool = bool(filter_list)
        else:
            exposed_via_alternate_services_bool = False

        should_raise_violation = (
            (bs_name_bool is not None and bs_name_bool) and\
            (allowed_direct_networks_bool is not None and\
             allowed_direct_networks_bool) and\
            (exposed_via_alternate_service_bool is not None and\
             exposed_via_alternate_service_bool))

        if should_raise_violation:
            yield self.RuleViolation(
                resource_type='project',
                resource_id=the_backend_service.project_number,
                rule_name=self.rule_name,
                rule_index=self.rule_index,
                violation_type='IAP_VIOLATION',
                backend_service_name=the_backend_service.name,
                direct_access_networks=direct_access_networks,
                exposed_via_services=exposed_via_services)

    RuleViolation = namedtuple('RuleViolation',
                               ['resource_type', 'resource_id', 'rule_name',
                                'rule_index', 'violation_type',
                                'backend_service_name', 'direct_access_networks',
                                'exposed_via_services'])
