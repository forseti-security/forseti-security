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

"""Rules engine for organizations, folders, and projects.

Builds the RuleBook (IamRuleBook) from the rule definitions (file either
stored locally or in GCS) and compares a policy against the RuleBook to
determine whether there are violations.
"""

import itertools
import threading

from google.cloud.forseti.common.gcp_type import errors as resource_errors
from google.cloud.forseti.common.gcp_type import iam_policy
from google.cloud.forseti.common.gcp_type import resource as resource_mod
from google.cloud.forseti.common.gcp_type import resource_util
from google.cloud.forseti.common.util import logger
from google.cloud.forseti.common.util import relationship
from google.cloud.forseti.scanner.audit import base_rules_engine as bre
from google.cloud.forseti.scanner.audit import rules as scanner_rules
from google.cloud.forseti.scanner.audit import errors as audit_errors

LOGGER = logger.get_logger(__name__)

VIOLATION_TYPE = 'IAM_POLICY_VIOLATION'


def _check_whitelist_members(rule_members=None, policy_members=None):
    """Whitelist: Check that policy members ARE in rule members.

    If a policy member is NOT found in the rule members, add it to
    the violating members.

    Args:
        rule_members (list): IamPolicyMembers allowed in the rule.
        policy_members (list): IamPolicyMembers in the policy.

    Return:
        list: Policy members NOT found in the whitelist (rule members).
    """
    violating_members = []
    for policy_member in policy_members:
        # check if policy_member is found in rule_members
        if not any(r.matches(policy_member) for r in rule_members):
            violating_members.append(policy_member)
    return violating_members


def _check_blacklist_members(rule_members=None, policy_members=None):
    """Blacklist: Check that policy members ARE NOT in rule members.

    If a policy member is found in the rule members, add it to the
    violating members.

    Args:
        rule_members (list): IamPolicyMembers allowed in the rule.
        policy_members (list): IamPolicyMembers in the policy.

    Return:
        list: Policy members found in the blacklist (rule members).
    """
    violating_members = [
        policy_member
        for policy_member in policy_members
        for rule_member in rule_members
        if rule_member.matches(policy_member)
    ]
    return violating_members


def _check_required_members(rule_members=None, policy_members=None):
    """Required: Check that rule members are in policy members.

    If a required rule member is NOT found in the policy members, add
    it to the violating members. Note that the check is different:
    it's reversed from the whitelist/blacklist (policy as a subset of
    rules vs rules as subset of policy).

    Args:
        rule_members (list): IamPolicyMembers allowed in the rule.
        policy_members (list): IamPolicyMembers in the policy.

    Return:
        list: Rule members not found in the policy (required-whitelist).
    """
    violating_members = []
    for rule_member in rule_members:
        # check if rule_member is found in policy_members
        if not any(rule_member.matches(m) for m in policy_members):
            violating_members.append(rule_member)
    return violating_members


class IamRulesEngine(bre.BaseRulesEngine):
    """Rules engine for org resources."""

    def __init__(self, rules_file_path, snapshot_timestamp=None):
        """Initialize.

        Args:
            rules_file_path (str): File location of rules.
            snapshot_timestamp (str): The snapshot to work with.
        """
        super(IamRulesEngine, self).__init__(
            rules_file_path=rules_file_path,
            snapshot_timestamp=snapshot_timestamp)
        self.rule_book = None

    def build_rule_book(self, global_configs):
        """Build IamRuleBook from the rules definition file.

        Args:
            global_configs (dict): Global configurations.
        """
        self.rule_book = IamRuleBook(
            global_configs,
            self._load_rule_definitions(),
            snapshot_timestamp=self.snapshot_timestamp)

    def find_violations(
            self, resource, policy, policy_bindings, force_rebuild=False):
        """Determine whether policy violates rules.

        Args:
            resource (gcp_type): The resource that the policy belongs to.
            policy (resource): The policy to compare against the rules.
                See https://cloud.google.com/iam/reference/rest/v1/Policy.
            policy_bindings (list): list of bindings found in `policy.data`
            force_rebuild (bool): If True, rebuilds the rule book.
                This will reload the rules definition file and add the
                rules to the book.

        Returns:
            iterable: A generator of rule violations.
        """
        if self.rule_book is None or force_rebuild:
            self.build_rule_book()

        violations = self.rule_book.find_violations(
            resource, policy, policy_bindings)

        return set(violations)

    def add_rules(self, rules):
        """Add rules to the rule book.

        Args:
            rules (list): The list of rules to add to the book.
        """
        if self.rule_book is not None:
            self.rule_book.add_rules(rules)


# pylint: disable=anomalous-backslash-in-string
class IamRuleBook(bre.BaseRuleBook):
    """The RuleBook for organization resources.

    Rules from the rules definition file are parsed and placed into a
    map, which associates the GCP resource with the particular rules
    defined for it.

    Sample rules (simplified):

    mode: whitelist
    Org 1234, bindings: roles/\*, members: user:\*@company.com
    Project p-a, bindings: roles/owner, members: user:pa-owner@company.com
    Project p-b, bindings: roles/owner, members: user:pb-owner@company.com

    Sample org structure:

            org 1234
           /        \
          f-1       p-c
         /  \
       p-a  p-b

    The rule book will be structured as:

    {
      Resource(org-1234): ResourceRule(org-1234, [ rules ... ]),
      Resource(p-a): ResourceRule(p-a, [ rules ... ]),
      Resource(p-a): ResourceRule(p-a, [ rules ... ])
    }

    """
    # pylint: enable=anomalous-backslash-in-string
    def __init__(self,
                 # TODO: To remove the unused global-configs here, it will be
                 # necessary to also update the base rules engine.
                 global_configs,  # pylint: disable= unused-argument
                 rule_defs=None,
                 snapshot_timestamp=None):
        """Initialize.

        Args:
            global_configs (dict): Global configurations.
            rule_defs (dict): The parsed dictionary of rules from the YAML
                definition file.
            snapshot_timestamp (str): The snapshot to lookup data.
        """
        super(IamRuleBook, self).__init__()
        self._rules_sema = threading.BoundedSemaphore(value=1)
        self.resource_rules_map = {}
        if not rule_defs:
            self.rule_defs = {}
        else:
            self.rule_defs = rule_defs
            self.add_rules(rule_defs)
        if snapshot_timestamp:
            self.snapshot_timestamp = snapshot_timestamp

    def __eq__(self, other):
        """Equals.

        Args:
            other (object): Object to compare.

        Returns:
            bool: True or False.
        """
        if not isinstance(other, type(self)):
            return NotImplemented
        return self.resource_rules_map == other.resource_rules_map

    def __ne__(self, other):
        """Not Equals.

        Args:
            other (object): Object to compare.

        Returns:
            bool: True or False.
        """
        return not self == other

    def __repr__(self):
        """Object representation.

        Returns:
            str: The object representation.
        """
        return 'IamRuleBook <{}>'.format(self.resource_rules_map)

    def add_rules(self, rule_defs):
        """Add rules to the rule book.

        Args:
            rule_defs (dict): Rules parsed from the rule definition file.
        """
        for (i, rule) in enumerate(rule_defs.get('rules', [])):
            self.add_rule(rule, i)

    def add_rule(self, rule_def, rule_index):
        """Add a rule to the rule book.

        The rule supplied to this method is the dictionary parsed from
        the rules definition file.

        For example, this rule...

            # rules yaml:
            rules:
              - name: a rule
                mode: whitelist
                resource:
                  - type: project
                    applies_to: self
                    resource_ids:
                      - my-project-123
                inherit_from_parents: true
                bindings:
                  - role: roles/editor
                    members:
                      - users:a@b.com

        ... gets parsed into:

            {
                'name': 'a rule',
                'mode': 'whitelist',
                'resource': {
                    'type': 'project',
                    'applies_to': self,
                    'resource_ids': ['my-project-id']
                },
                'inherit_from_parents': true,
                'bindings': [
                    {
                        'role': 'roles/editor',
                        'members': ['users:a@b.com']
                    }
                ]
            }

        Args:
            rule_def (dict): Contains rule definition properties.
            rule_index (int): The index of the rule from the rule definitions.
                Assigned automatically when the rule book is built.
        """
        self._rules_sema.acquire()

        try:
            resources = rule_def.get('resource')

            for resource in resources:
                resource_ids = resource.get('resource_ids')
                resource_type = None
                # TODO: collect these errors and output them in a log.
                # TODO: log the error and keep going
                try:
                    resource_type = resource_mod.ResourceType.verify(
                        resource.get('type'))
                except resource_errors.InvalidResourceTypeError:
                    raise audit_errors.InvalidRulesSchemaError(
                        'Missing resource type in rule {}'.format(rule_index))

                if not resource_ids or len(resource_ids) < 1:
                    raise audit_errors.InvalidRulesSchemaError(
                        'Missing resource ids in rule {}'.format(rule_index))

                # For each resource id associated with the rule, create a
                # mapping of resource => rules.
                for resource_id in resource_ids:
                    gcp_resource = resource_util.create_resource(
                        resource_id=resource_id,
                        resource_type=resource_type)

                    # TODO: Rewrite this as a list comprehension.
                    # pylint: disable=bad-builtin
                    rule_bindings = filter(
                        None,
                        [iam_policy.IamPolicyBinding.create_from(b) for b in
                         rule_def.get('bindings')]
                    )
                    rule = scanner_rules.Rule(rule_name=rule_def.get('name'),
                                              rule_index=rule_index,
                                              bindings=rule_bindings,
                                              mode=rule_def.get('mode'))

                    rule_applies_to = resource.get('applies_to')
                    rule_key = (gcp_resource, rule_applies_to)

                    # See if we have a mapping of the resource and rule
                    resource_rules = self.resource_rules_map.get(rule_key)

                    # If no mapping exists, create it.
                    if not resource_rules:
                        resource_rules = ResourceRules(
                            resource=gcp_resource,
                            applies_to=rule_applies_to,
                            inherit_from_parents=rule_def.get(
                                'inherit_from_parents', False))
                        self.resource_rules_map[rule_key] = resource_rules

                    # If the rule isn't in the mapping, add it.
                    if rule not in resource_rules.rules:
                        resource_rules.rules.add(rule)
        finally:
            self._rules_sema.release()

    def _get_resource_rules(self, resource):
        """Get all the resource rules for (resource, RuleAppliesTo.*).

        Args:
            resource (Resource): The resource to find in the ResourceRules map.

        Returns:
            list: A list of ResourceRules.
        """
        resource_rules = []

        for rule_applies_to in scanner_rules.RuleAppliesTo.apply_types:
            if (resource, rule_applies_to) in self.resource_rules_map:
                resource_rules.append(self.resource_rules_map.get(
                    (resource, rule_applies_to)))

        return resource_rules

    def find_violations(self, resource, policy, policy_bindings):
        """Find policy binding violations in the rule book.

        Args:
            resource (gcp_type): The GCP resource associated with the
                policy binding.
                This is where we start looking for rule violations and
                we move up the resource hierarchy (if permitted by the
                resource's "inherit_from_parents" property).
            policy (forseti_data_model_resource): The policy to compare
                against the rules.
                See https://cloud.google.com/iam/reference/rest/v1/Policy.
            policy_bindings (list): A list of IamPolicyBindings.

        Returns:
            iterable: A generator of the rule violations.
        """
        violations = itertools.chain()

        resource_ancestors = (
            relationship.find_ancestors(resource, policy.full_name))

        for curr_resource in resource_ancestors:
            wildcard_resource = resource_util.create_resource(
                resource_id='*', resource_type=curr_resource.type)
            resource_rules = self._get_resource_rules(curr_resource)
            resource_rules.extend(self._get_resource_rules(wildcard_resource))

            # Set to None, because if the direct resource (e.g. project)
            # doesn't have a specific rule, we still should check the
            # ancestry to see if the resource's parents have any rules
            # that apply to the children.
            inherit_from_parents = None

            for resource_rule in resource_rules:
                if not self._rule_applies_to_resource(
                        resource, curr_resource, resource_rule):
                    continue

                violations = itertools.chain(
                    violations,
                    resource_rule.find_mismatches(resource, policy_bindings))

                inherit_from_parents = resource_rule.inherit_from_parents

            # If the rule does not inherit the parents' rules, stop.
            # Due to the way rules are structured, we only define the
            # "inherit" property once per rule. So even though a rule
            # may apply to multiple resources, it will only have one
            # value for "inherit_from_parents".
            if not inherit_from_parents and inherit_from_parents is not None:
                break

        return violations

    @staticmethod
    def _rule_applies_to_resource(resource, curr_resource, resource_rule):
        """Check whether rules match if the applies_to condition is met.

        SELF: check rules if the starting resource == current resource
        CHILDREN: check rules if starting resource != current resource
        SELF_AND_CHILDREN: always check rules

        Args:
            resource (Resource): The main resource we're checking the rule
                against.
            curr_resource (Resource): A resource that is in the main resource's
                ancestry.
            resource_rule (ResourceRule): The rule associated with the resource.

        Returns:
            bool: True if rule applies to the resource, otherwise false.
        """
        applies_to_self = (resource_rule.applies_to ==
                           scanner_rules.RuleAppliesTo.SELF and
                           resource == curr_resource)
        applies_to_children = (resource_rule.applies_to ==
                               scanner_rules.RuleAppliesTo.CHILDREN and
                               resource != curr_resource)
        applies_to_both = (resource_rule.applies_to ==
                           scanner_rules.RuleAppliesTo.SELF_AND_CHILDREN)

        return applies_to_self or applies_to_children or applies_to_both


class ResourceRules(object):
    """An association of a resource to rules."""

    def __init__(self,
                 resource=None,
                 rules=None,
                 applies_to=scanner_rules.RuleAppliesTo.SELF,
                 inherit_from_parents=False):
        """Initialize.

        Args:
            resource (Resource): The resource to associate with the rule.
            rules (set): A set with rules to associate with the resource.
            applies_to (str): Whether the rule applies to the resource's
                self, children, or both.
            inherit_from_parents (bool): Whether the rule lookup should request
                the resource's ancestor's rules.
        """
        if not isinstance(rules, set):
            rules = set([])
        self.resource = resource
        self.rules = rules
        self.applies_to = scanner_rules.RuleAppliesTo.verify(applies_to)
        self.inherit_from_parents = inherit_from_parents

        self._rule_mode_methods = {
            scanner_rules.RuleMode.WHITELIST: _check_whitelist_members,
            scanner_rules.RuleMode.BLACKLIST: _check_blacklist_members,
            scanner_rules.RuleMode.REQUIRED: _check_required_members,
        }

    def __eq__(self, other):
        """Equals

        Args:
            other (object): The object to compare.

        Returns:
            bool: True or False
        """
        if not isinstance(other, type(self)):
            return NotImplemented
        return (self.resource == other.resource and
                self.rules == other.rules and
                self.applies_to == other.applies_to and
                self.inherit_from_parents == other.inherit_from_parents)

    def __ne__(self, other):
        """Not Equals

        Args:
            other (object): The object to compare.

        Returns:
            bool: True or False
        """
        return not self == other

    def __repr__(self):
        """Object representation.

        Returns:
            str: The object representation.
        """
        return ('ResourceRules<resource={}, rules={}, '
                'applies_to={}, inherit_from_parents={}>').format(
                    self.resource,
                    self.rules,
                    self.applies_to,
                    self.inherit_from_parents)

    def find_mismatches(self, resource, policy_bindings):
        """Determine if the policy binding matches this rule's criteria.

        How the member matching operates:

        1. Whitelist: policy members match at least one rule member
        2. Blacklist: policy members must not match any rule members
        3. Require: rule members must all be found in policy members

        Args:
            resource (Resource): The resource that the policy belongs to.
            policy_bindings (list): The list of IamPolicyBindings
                to compare to this rule's bindings.

        Returns:
            iterable: The violations generator
        """
        violations = itertools.chain()
        for rule in self.rules:
            if rule.mode == scanner_rules.RuleMode.REQUIRED:
                violations = itertools.chain(
                    violations,
                    self._check_required_rules(
                        resource, rule, policy_bindings))
            else:
                violations = itertools.chain(
                    violations,
                    self._check_whitelistblacklist_rules(
                        resource, rule, policy_bindings))

        return violations

    def _check_required_rules(self, resource, rule, policy_bindings):
        """Check required rule.

        Args:
            resource (Resource): The resource that the policy belongs to.
            policy_bindings (list): The list of IamPolicyBindings.
            rule (Rule): The rule to check.

        Yields:
            iterable: A generator of RuleViolations.
        """
        found_role = False
        violating_bindings = {}
        # If the rule's binding role is found in the policy,
        # check the policy members to see if all rule binding
        # members are found.
        # Any outstanding rule bindings (role => members) should be reported.
        for rule_binding in rule.bindings:
            for policy_binding in policy_bindings:
                violating_members = None
                if rule_binding.role_pattern.match(policy_binding.role_name):
                    found_role = True
                    violating_members = (self._dispatch_rule_mode_check(
                        mode=rule.mode,
                        rule_members=rule_binding.members,
                        policy_members=policy_binding.members))
                if violating_members:
                    violating_bindings[
                        rule_binding.role_name] = violating_members

        if not found_role:
            violating_bindings = {b.role_name: b.members for b in rule.bindings}

        if violating_bindings:
            for (role_name, members) in violating_bindings.iteritems():
                yield scanner_rules.RuleViolation(
                    resource_type=resource.type,
                    resource_id=resource.id,
                    full_name=resource.full_name,
                    rule_name=rule.rule_name,
                    rule_index=rule.rule_index,
                    violation_type=VIOLATION_TYPE,
                    role=role_name,
                    members=tuple(members),
                    resource_data=resource.data)

    def _check_whitelistblacklist_rules(self, resource, rule, policy_bindings):
        """Check whitelist and blacklist rules.

        Args:
            resource (Resource): The resource that the policy belongs to.
            rule (Rule): The rule to check.
            policy_bindings (list): The list of IamPolicyBindings.

        Yields:
            iterable: A generator of RuleViolations.
        """
        for policy_binding in policy_bindings:
            for rule_binding in rule.bindings:
                # If the rule's role pattern matches the policy binding's
                # role pattern, then check the members to see whether they
                # match, according to the rule mode.
                violating_members = None
                if rule_binding.role_pattern.match(policy_binding.role_name):
                    violating_members = (self._dispatch_rule_mode_check(
                        mode=rule.mode,
                        rule_members=rule_binding.members,
                        policy_members=policy_binding.members))
                if violating_members:
                    yield scanner_rules.RuleViolation(
                        resource_type=resource.type,
                        resource_id=resource.id,
                        full_name=resource.full_name,
                        rule_name=rule.rule_name,
                        rule_index=rule.rule_index,
                        violation_type=VIOLATION_TYPE,
                        role=policy_binding.role_name,
                        members=tuple(violating_members),
                        resource_data=resource.data)

    def _dispatch_rule_mode_check(self, mode, rule_members=None,
                                  policy_members=None):
        """Determine which rule mode method to execute for rule audit.

        Args:
            mode (str): The rule mode.
            rule_members (list): The rule binding members.
            policy_members (list): The policy binding members.

        Returns:
            list: The result of calling the dispatched method.
        """
        return self._rule_mode_methods[mode](
            rule_members=rule_members,
            policy_members=policy_members)
