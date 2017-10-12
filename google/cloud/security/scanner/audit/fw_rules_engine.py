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

from collections import namedtuple

from google.cloud.security.common.gcp_type import firewall_rule
from google.cloud.security.common.util import log_util
from google.cloud.security.scanner.audit import rules as scanner_rules


LOGGER = log_util.get_logger(__name__)


# pylint: disable=too-many-instance-attributes
class Rule(object):
    """Rule properties from the firewall rules definitions file.
    Also finds violations.
    """

    def __init__(self,
                 rule_name=None,
                 match_policies=None,
                 verify_policies=None,
                 mode=scanner_rules.RuleMode.WHITELIST,
                 applies_to=scanner_rules.RuleAppliesTo.SELF,
                 inherit_from_parents=False,
                 exact_match=True):
        """Initialize.

        Args:
          rule_name (str): The name of the rule.
          match_policies (list): A list of policy dictionaries.
          verify_policies (list): A list of policy dictionaries.
          mode (RuleMode): The RuleMode for this rule.
          applies_to (RuleAppliesTo): The resources this rule applies to.
          inherit_from_parents (bool): Whether this rule inherits from parents.
          exact_match (bool): Whether to exactly match required rules.
        """
        self.name = rule_name
        self._match_policies = match_policies
        self._match_rules = None
        self._exact_match = exact_match
        self.mode = mode
        self._verify_policies = verify_policies
        self._verify_rules = None
        self.applies_to = scanner_rules.RuleAppliesTo.verify(applies_to)
        self.inherit_from_parents = inherit_from_parents

    @staticmethod
    def create_rules(policies):
        """Creates FirewallRules from policies.

        Args:
          policies (list): A list of policy dictionaries.

        Returns:
          list: A list of FirewallRule.
        """
        match_rules = []
        for policy in policies:
            rule = firewall_rule.FirewallRule(**policy)
            match_rules.append(rule)
        return match_rules

    @property
    def match_rules(self):
        """The FirewallRules used to filter policies.

        Returns:
          list: A list of FirewallRule.
        """
        if not self._match_rules:
            self._match_rules = self.create_rules(self._match_policies)
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
        recommended_actions = []
        for rule in self.match_rules:
            if is_rule_exists_violation(rule, firewall_policies,
                                        self._exact_match):
                recommended_action = self._create_recommendation(
                    'INSERT_FIREWALL_RULE', rule)
                recommended_actions.append(recommended_action)

        for policy in firewall_policies:
            if not any(policy == rule for rule in self.match_rules):
                recommended_action = self._create_recommendation(
                    'DELETE_FIREWALL_RULE', policy)
                recommended_actions.append(recommended_action)

        if recommended_actions:
            yield self._create_violation(
                firewall_policies, 'FIREWALL_MATCHES_VIOLATION',
                recommended_actions=[recommended_action])

    def _yield_required_violations(self, firewall_policies):
        """Finds missing policies that are required.

        Args:
          firewall_policies (list): A list of FirewallRules to check.

        Yields:
          iterable: A generator of RuleViolations.
        """
        for rule in self.match_rules:
            if is_rule_exists_violation(rule, firewall_policies,
                                        self._exact_match):
                recommended_action = self._create_recommendation(
                    'INSERT_FIREWALL_RULE', self)
                yield self._create_violation(
                    firewall_policies, 'FIREWALL_REQUIRED_VIOLATION',
                    recommended_actions=[recommended_action])

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
                recommended_action = self._create_recommendation(
                    'DELETE_FIREWALL_RULE', policy)
                yield self._create_violation(
                    [policy], 'FIREWALL_WHITELIST_VIOLATION',
                    recommended_actions=[recommended_action])

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
                recommended_action = self._create_recommendation(
                    'DELETE_FIREWALL_RULE', policy)
                yield self._create_violation(
                    [policy], 'FIREWALL_BLACKLIST_VIOLATION',
                    recommended_actions=[recommended_action])

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
            resource_type='firewall_policy',
            resource_id=policies[0].project_id,
            rule_name=self.name,
            violation_type=violation_type,
            policy_names=[p.name for p in policies],
            recommended_actions=recommended_actions,
        )

    @staticmethod
    def _create_recommendation(recommended_action, policy):
        """Creates a recommendation string.

        Args:
          recommended_action (str): The type of action to take.
          policy (str): The policy to take the action on.

        Returns:
          str: A recommended action string.
        """
        return 'Recommended Action %s: %s' % (recommended_action, policy.name)
# pylint: enable=too-many-instance-attributes

# Rule violation.
# resource_type: string
# resource_id: string
# rule_name: string
# violation_type: FIREWALL_VIOLATION
# policy_names: string
# recommeded_action: string
RuleViolation = namedtuple('RuleViolation',
                           ['resource_type', 'resource_id', 'rule_name',
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
