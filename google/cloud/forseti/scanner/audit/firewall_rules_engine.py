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

"""Rules engine for firewall rules."""

import itertools
import threading
from collections import namedtuple

from google.cloud.forseti.common.data_access import org_resource_rel_dao
from google.cloud.forseti.common.gcp_type import firewall_rule
from google.cloud.forseti.common.gcp_type import resource as resource_mod
from google.cloud.forseti.common.gcp_type import resource_util
from google.cloud.forseti.common.util import log_util
from google.cloud.forseti.scanner.audit import base_rules_engine as bre
from google.cloud.forseti.scanner.audit import rules as scanner_rules


LOGGER = log_util.get_logger(__name__)


class Error(Exception):
    """Base error class for the module."""


class DuplicateFirewallRuleError(Error):
    """Raised if a rule id is reused in the rule definitions, must be unique."""


class DuplicateFirewallGroupError(Error):
    """Raised if group id is reused in the group definitions, must be unique."""


class RuleDoesntExistError(Error):
    """Raised if a rule group tries to add a rule that doesn't exist."""


class GroupDoesntExistError(Error):
    """Raised if an org policy tries to add a group that doesn't exist."""


class InvalidRuleDefinition(Error):
    """Raised if a rule definition is invalid."""


class InvalidGroupDefinition(Error):
    """Raised if a group definition is invalid."""


class InvalidOrgDefinition(Error):
    """Raised if a org definition is invalid."""


class FirewallRulesEngine(bre.BaseRulesEngine):
    """Rules engine for firewall resources."""

    def __init__(self, rules_file_path, snapshot_timestamp=None):
        """Initialize.

        Args:
          rules_file_path (str): File location of rules.
          snapshot_timestamp (str): The snapshot to work with.
        """
        super(FirewallRulesEngine, self).__init__(
            rules_file_path=rules_file_path,
            snapshot_timestamp=snapshot_timestamp)
        self._repository_lock = threading.RLock()
        self.rule_book = None

    def build_rule_book(self, global_configs):
        """Build RuleBook from the rule definition file.

        Args:
          global_configs (dict): Global configurations.
        """
        del global_configs  # unused.
        with self._repository_lock:
            rule_file_dict = self._load_rule_definitions()
            rule_defs = rule_file_dict.get('rules', [])
            group_defs = rule_file_dict.get('rule_groups', [])
            org_policy = rule_file_dict.get('org_policy', [])
            self.rule_book = RuleBook(
                rule_defs=rule_defs,
                group_defs=group_defs,
                org_policy=org_policy,
                snapshot_timestamp=self.snapshot_timestamp)

    def find_policy_violations(self, resource, policy, force_rebuild=False):
        """Determine whether policy violates rules.

        Args:
          resource (Resource): The resource that the policy belongs to.
          policy (dict): The policy to compare against the rules.
          force_rebuild (bool): If True, rebuilds the rule book.
            This will reload the rules definition file and add the rules to the
            book.

        Returns:
            list: A list of the rule violations.
        """
        if self.rule_book is None or force_rebuild:
            self.build_rule_book(self.full_rules_path)

        violations = self.rule_book.find_violations(resource, policy)

        return list(violations)


class RuleBook(bre.BaseRuleBook):
    """The RuleBook for firewall auditing.

    Rules from the rules definition file are parsed and then the hierarchy and
    enforcement points are parsed. Rules then are assessed at the first
    applicable point in the ancestory tree that has rules.

    Sample org structure:

            org 1234
           /        \
          f-1       p-c
         /  \
       p-a  p-b

    Rules can be applied at any node above. When a policy is being audited,
    it the rulebook will start at the lowest level (the project) and will
    walk up the hierarchy until it reaches the first instance with rules and
    these are the only rules that are checked.
    """

    def __init__(self,
                 rule_defs=None,
                 snapshot_timestamp=None,
                 group_defs=None,
                 org_policy=None):
        """Initialize.

        Args:
          rule_defs (list): The parsed list of dictionary rules from the YAML
            definition file.
          snapshot_timestamp (str): The snapshot to work with.
          group_defs (list): The parsed list of dictionary group ids to rules.
          org_policy (dict): The parsed org policy configuration.
        """
        super(RuleBook, self).__init__()
        self.rule_indices = {}
        self.rules_map = {}
        self.rule_groups_map = {}
        self.org_policy_rules_map = {}
        self.snapshot_timestamp = snapshot_timestamp or None
        self._repository_lock = threading.RLock()
        if rule_defs:
            self.add_rules(rule_defs)
        if group_defs:
            self.add_rule_groups(group_defs)
        if org_policy:
            self.add_org_policy(org_policy)

    def add_rules(self, rule_defs):
        """Adds rules to rule book.

        Args:
          rule_defs (list): Rule definition dictionaries from yaml config file.

        Raises:
          InvalidRuleDefinition: If the rule is missing required fields or the
            fields have invalid values.
        """
        with self._repository_lock:
            for i, rule_def in enumerate(rule_defs):
                if rule_def is not None:
                    self.add_rule(rule_def, i)

    def add_rule(self, rule_def, rule_index):
        """Adds a rule to the rule book.

        Args:
          rule_def (Rule): A Rule used to check for violations.
          rule_index (int): Used for logs.

        Raises:
          DuplicateFirewallRuleError: When the rule by the same name exists.
        """
        rule = Rule.from_config(rule_def)
        if rule.id in self.rules_map:
            raise DuplicateFirewallRuleError(
                'Rule id "%s" already in rules (rule %s)' % (
                    rule.id, rule_index))
        self.rule_indices[rule.id] = rule_index
        self.rules_map[rule.id] = rule

    def add_rule_groups(self, group_defs):
        """Creates group to rule matching.

        Args:
          group_defs (dict): A dictionary with a group id and a list of rule ids
            that will be included by including this group in a policy.

        Raises:
          DuplicateFirewallGroupError: Raised if the group id already exists.
          RuleDoesntExistError: Raised if a rule included in the group does not
            exist.
          InvalidGroupDefinition: Raised if a group definition is invalid.
        """
        for group_def in group_defs:
            group_id = group_def.get('group_id')
            if not group_id:
                raise InvalidGroupDefinition('Group requires a group id')
            if group_id in self.rule_groups_map:
                raise DuplicateFirewallGroupError(
                    'Group id already exists: %s' % group_id)
            rule_ids = group_def.get('rule_ids')
            if not rule_ids:
                raise InvalidGroupDefinition(
                    'Group "%s" does not have any rules' % group_id)
            for rule_id in rule_ids:
                if rule_id not in self.rules_map:
                    raise RuleDoesntExistError(
                        'Rule id "%s" does not exist, cannot be in group' %
                        rule_id)
            self.rule_groups_map[group_id] = rule_ids

    def add_org_policy(self, org_def):
        """Creates org policy and rule mapping.

        Sample org structure:

                org 1234
               /        \
              f-1       p-c
             /  \
           p-a  p-b

        Rules can be applied at any node above. When a policy is being audited,
        it the rulebook will start at the lowest level (the project) and will
        walk up the hierarchy until it reaches the first instance with rules and
        these are the only rules that are checked.

        Args:
          org_def (dict): A dictionary of resource ids and enforced rules.

        Raises:
          RuleDoesntExistError: Raised if a rule included in the group does not
            exist.
          GroupDoesntExistError: Raised if a group included in an org policy
            does not exist.
          InvalidOrgDefinition: Raised if org policy doesn't have resources.
        """
        resources = org_def.get('resources', [])
        if not resources:
            raise InvalidOrgDefinition('Org policy does not have any resources')
        for resource in resources:
            resource_type = resource_mod.ResourceType.verify(
                resource.get('type'))
            ids = resource.get('resource_ids', [])
            rules = resource.get('rules', {})
            groups = rules.get('group_ids', [])
            expanded_rules = set()
            for group_id in groups:
                if group_id not in self.rule_groups_map:
                    raise GroupDoesntExistError(
                        'Group "%s" does not exist' % group_id)
                expanded_group = self.rule_groups_map.get(group_id, [])
                expanded_rules.update(expanded_group)
            for rule_id in rules.get('rule_ids', []):
                if rule_id not in self.rules_map:
                    raise RuleDoesntExistError(
                        'Rule id "%s" does not exist' % rule_id)
                expanded_rules.add(rule_id)
            for resource_id in ids:
                gcp_resource = resource_util.create_resource(
                    resource_id=resource_id,
                    resource_type=resource_type)
                self.org_policy_rules_map[gcp_resource] = sorted(expanded_rules)


    def find_violations(self, resource, policies):
        """Find policy binding violations in the rule book.

        Args:
            resource (Resource): The GCP resource associated with the
                policy binding.
                This is where we start looking for rule violations and
                we move up the resource hierarchy (if permitted by the
                resource's "inherit_from_parents" property).
            policies(list): A list of FirewallRule policies.

        Returns:
            iterable: A generator of the rule violations.
        """
        violations = itertools.chain()

        resource_ancestors = (
            org_resource_rel_dao.find_ancestors_by_hierarchial_name(
                resource, policy.full_name))

        for curr_resource in resource_ancestors:
            if curr_resource in self.org_policy_rules_map:
                org_policy_rules = self.org_policy_rules_map.get(
                    curr_resource, [])
                for rule_id in org_policy_rules:
                    rule = self.rules_map[rule_id]
                    violations = itertools.chain(
                        violations,
                        rule.find_policy_violations(policies))
                break  # Only the first rules found in the ancestry are applied
        return violations


class Rule(object):
    """Rule properties from the firewall rules definitions file.
    Also finds violations.
    """

    VALID_RULE_MODES = frozenset([
        scanner_rules.RuleMode.WHITELIST,
        scanner_rules.RuleMode.BLACKLIST,
        scanner_rules.RuleMode.REQUIRED,
        scanner_rules.RuleMode.MATCHES,
    ])

    def __init__(self,
                 rule_id=None,
                 match_policies=None,
                 verify_policies=None,
                 mode=scanner_rules.RuleMode.WHITELIST,
                 exact_match=True):
        """Initialize.

        Args:
          rule_id (str): The id of the rule.
          match_policies (list): A list of policy dictionaries.
          verify_policies (list): A list of policy dictionaries.
          mode (RuleMode): The RuleMode for this rule.
          exact_match (bool): Whether to exactly match required rules.
        """
        self.id = rule_id
        self._match_policies = match_policies
        self._match_rules = None
        self._exact_match = exact_match
        self.mode = mode
        self._verify_policies = verify_policies
        self._verify_rules = None

    def __hash__(self):
        """Makes a hash of the rule id.

        Returns:
          int: The hash of the rule id.
        """
        return hash(self.id)

    @classmethod
    def from_config(cls, rule_def):
        """Creates a Rule from a config file.

        Args:
          rule_def (dict): A dictionary rule definition parsed from YAML config.

        Returns:
          Rule: A rule created from the rule definition.

        Raises:
          InvalidRuleDefinition: If rule is missing required fields.
        """
        rule_id = rule_def.get('rule_id')
        if not rule_id:
            raise InvalidRuleDefinition('Rule requires rule_id')
        mode = rule_def.get('mode')
        if not mode:
            raise InvalidRuleDefinition('Rule requires mode')
        mode = mode.lower()
        if mode not in cls.VALID_RULE_MODES:
            raise InvalidRuleDefinition('Mode %s is not in valid modes: %s'
                                        % (mode, cls.VALID_RULE_MODES))
        match_policies = rule_def.get('match_policies', [])
        verify_policies = rule_def.get('verify_policies', [])
        if mode in ['whitelist', 'blacklist']:
            if not match_policies or not verify_policies:
                raise InvalidRuleDefinition(
                    'Whitelist and blacklist rules require match and verify '
                    'policies')
        if mode in ['required', 'matches']:
            if not match_policies:
                raise InvalidRuleDefinition(
                    'Required and matches rules require match policies')
            if verify_policies:
                raise InvalidRuleDefinition(
                    'Required and matches rules cannot have verify policies')
        return Rule(
            rule_id=rule_id,
            match_policies=match_policies,
            verify_policies=verify_policies,
            mode=mode,
            exact_match=rule_def.get('exact_match', True),
        )

    @staticmethod
    def create_rules(policies, validate=False):
        """Creates FirewallRules from policies.

        Args:
          policies (list): A list of policy dictionaries.
          validate (bool): Whether to validate that this is a valid firewall
            rule (one that can be passed to the API).

        Returns:
          list: A list of FirewallRule.
        """
        match_rules = []
        for policy in policies:
            rule = firewall_rule.FirewallRule.from_dict(
                policy, validate=validate)
            match_rules.append(rule)
        return match_rules

    @property
    def match_rules(self):
        """The FirewallRules used to filter policies.

        Returns:
          list: A list of FirewallRule.
        """
        if not self._match_rules:
            validate = self.mode in {
                scanner_rules.RuleMode.REQUIRED,
                scanner_rules.RuleMode.MATCHES
            }
            self._match_rules = self.create_rules(
                self._match_policies, validate=validate)
        return self._match_rules

    @property
    def verify_rules(self):
        """The FirewallRules used to check policies.

        Returns:
          list: A list of FirewallRule.
        """
        if not self._verify_rules:
            self._verify_rules = self.create_rules(self._verify_policies)
        return self._verify_rules

    def find_policy_violations(self, firewall_policies):
        """Finds policy violations in a list of firewall policies.

        Args:
          firewall_policies (list): A list of FirewallRule.

        Returns:
          iterable: A generator of RuleViolations.
        """
        if self.mode == scanner_rules.RuleMode.MATCHES:
            violations = self._yield_match_violations(firewall_policies)
        elif self.mode == scanner_rules.RuleMode.REQUIRED:
            violations = self._yield_required_violations(firewall_policies)
        elif self.mode == scanner_rules.RuleMode.WHITELIST:
            violations = self._yield_whitelist_violations(firewall_policies)
        elif self.mode == scanner_rules.RuleMode.BLACKLIST:
            violations = self._yield_blacklist_violations(firewall_policies)
        return violations

    def _yield_match_violations(self, firewall_policies):
        """Finds policies that don't match the required policy.

        Args:
          firewall_policies (list): A list of FirewallRules to check.

        Yields:
          iterable: A generator of RuleViolations.
        """
        inserts = set([])
        deletes = set([])
        for i, rule in enumerate(self.match_rules):
            if is_rule_exists_violation(rule, firewall_policies,
                                        self._exact_match):
                inserts.add('%s: rule %s' % (self.id, i))

        for policy in firewall_policies:
            if is_rule_exists_violation(policy, self.match_rules,
                                        self._exact_match):
                deletes.add(policy.name)

        updates = inserts & deletes
        inserts, deletes = (inserts-updates, deletes-updates)

        if inserts or deletes or updates:
            yield self._create_violation(
                firewall_policies, 'FIREWALL_MATCHES_VIOLATION',
                recommended_actions={
                    'INSERT_FIREWALL_RULES': sorted(inserts),
                    'DELETE_FIREWALL_RULES': sorted(deletes),
                    'UPDATE_FIREWALL_RULES': sorted(updates),
                })

    def _yield_required_violations(self, firewall_policies):
        """Finds missing policies that are required.

        Args:
          firewall_policies (list): A list of FirewallRules to check.

        Yields:
          iterable: A generator of RuleViolations.
        """
        for i, rule in enumerate(self.match_rules):
            if is_rule_exists_violation(rule, firewall_policies,
                                        self._exact_match):
                yield self._create_violation(
                    firewall_policies, 'FIREWALL_REQUIRED_VIOLATION',
                    recommended_actions={
                        'INSERT_FIREWALL_RULES': [
                            '%s: rule %s' % (self.id, i)
                        ],
                    })

    def _yield_whitelist_violations(self, firewall_policies):
        """Finds policies that aren't whitelisted.

        Args:
          firewall_policies (list): A list of FirewallRules to check.

        Yields:
          iterable: A generator of RuleViolations.
        """
        for policy in firewall_policies:
            if not any([policy > rule for rule in self.match_rules]):
                continue
            if is_whitelist_violation(self.verify_rules, policy):
                yield self._create_violation(
                    [policy], 'FIREWALL_WHITELIST_VIOLATION',
                    recommended_actions={
                        'DELETE_FIREWALL_RULES': [policy.name],
                    })

    def _yield_blacklist_violations(self, firewall_policies):
        """Finds blacklisted policies.

        Args:
          firewall_policies (list): A list of FirewallRules to check.

        Yields:
          iterable: A generator of RuleViolations.
        """
        for policy in firewall_policies:
            if not any([policy > rule for rule in self.match_rules]):
                continue
            if is_blacklist_violation(self.verify_rules, policy):
                yield self._create_violation(
                    [policy], 'FIREWALL_BLACKLIST_VIOLATION',
                    recommended_actions={
                        'DELETE_FIREWALL_RULES': [policy.name],
                    })

    def _create_violation(self, policies, violation_type,
                          recommended_actions=None):
        """Creates a RuleViolation.

        Args:
          policies (list): A list of FirewallRule that violate the policy.
          violation_type (str): The type of violation.
          recommended_actions (list): The list of actions to take.

        Returns:
          RuleViolation: A RuleViolation for the given policies.

        Raises:
          ValueError: If no policies are passed in.
        """
        if not policies:
            raise ValueError('No policies in violation')
        return RuleViolation(
            resource_type='firewall_rule',
            resource_id=policies[0].project_id,
            rule_id=self.id,
            violation_type=violation_type,
            policy_names=[p.name for p in policies],
            recommended_actions=recommended_actions,
        )

# Rule violation.
# resource_type: string
# resource_id: string
# rule_name: string
# violation_type: FIREWALL_VIOLATION
# policy_names: string
# recommeded_action: string
RuleViolation = namedtuple('RuleViolation',
                           ['resource_type', 'resource_id', 'rule_id',
                            'violation_type', 'policy_names',
                            'recommended_actions'])

def is_whitelist_violation(rules, policy):
    """Checks if the policy is not a subset of those allowed by the rules.

    Args:
      rules (list): A list of FirewallRule that the policy must be a subset of.
      policy (FirweallRule): A FirewallRule.

    Returns:
      bool: If the policy is a subset of one of the allowed rules or not.
    """
    return not any([policy < rule for rule in rules])

def is_blacklist_violation(rules, policy):
    """Checks if the policy is a superset of any not allowed by the rules.

    Args:
      rules (list): A list of FirewallRule that the policy must be a subset of.
      policy (FirweallRule): A FirewallRule.

    Returns:
      bool: If the policy is a superset of one of the blacklisted rules or not.
    """
    return any([policy > rule for rule in rules])

def is_rule_exists_violation(rule, policies, exact_match=True):
    """Checks if the rule is the same as one of the policies.

    Args:
      rule (FirweallRule): A FirewallRule.
      policies (list): A list of FirewallRule that must have the rule.
      exact_match (bool): Whether to match the rule exactly.

    Returns:
      bool: If the required rule is in the policies.
    """
    if exact_match:
        return not any([policy == rule for policy in policies])
    return not any([policy.is_equilvalent(rule) for policy in policies])
