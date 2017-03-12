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

"""Rules engine for organizations, folders, and projects.

Builds the RuleBook (OrgRuleBook) from the rule definitions (file either
stored locally or in GCS) and compares a policy against the RuleBook to
determine whether there are violations.
"""

import itertools
import threading

from collections import namedtuple
# pylint: disable=line-too-long
from google.cloud.security.common.gcp_type.errors import InvalidResourceTypeError
from google.cloud.security.common.gcp_type.iam_policy import IamPolicyBinding
from google.cloud.security.common.gcp_type.resource import ResourceType
from google.cloud.security.common.gcp_type.resource_util import ResourceUtil
from google.cloud.security.scanner.audit.base_rules_engine import BaseRuleBook
from google.cloud.security.scanner.audit.base_rules_engine import BaseRulesEngine
from google.cloud.security.scanner.audit.errors import InvalidRulesSchemaError
# pylint: enable=line-too-long


class OrgRulesEngine(BaseRulesEngine):
    """Rules engine for org resources."""

    def __init__(self, rules_file_path):
        super(OrgRulesEngine, self).__init__(
            rules_file_path=rules_file_path,
            logger_name=__name__)
        self.rule_book = None

    def build_rule_book(self):
        """Build OrgRuleBook from the rules definition file."""
        self.rule_book = OrgRuleBook(self._load_rule_definitions())

    def find_policy_violations(self, resource, policy, force_rebuild=False):
        """Determine whether policy violates rules.

        Args:
            resource: The resource that the policy belongs to.
            policy: The policy to compare against the rules.
                See https://cloud.google.com/iam/reference/rest/v1/Policy.
            force_rebuild: If True, rebuilds the rule book. This will reload
                the rules definition file and add the rules to the book.

        Returns:
            A list of tuples containing the policy diffs.
        """
        if self.rule_book is None or force_rebuild:
            self.build_rule_book()

        violations = []

        for binding in policy.get('bindings', []):
            binding_violations = (
                self.rule_book.find_violations(resource, binding))
            violations.extend(binding_violations)

        return violations

    def add_rules(self, rules):
        """Add rules to the rule book."""
        if self.rule_book is not None:
            self.rule_book.add_rules(rules)


class RuleAppliesTo(object):
    """What the rule applies to. (Default: SELF) """

    SELF = 'self'
    CHILDREN = 'children'
    SELF_AND_CHILDREN = 'self_and_children'
    apply_types = frozenset([SELF, CHILDREN, SELF_AND_CHILDREN])

    @classmethod
    def verify(cls, applies_to):
        """Verify whether the applies_to is valid."""
        if applies_to not in cls.apply_types:
            raise InvalidRulesSchemaError(
                'Invalid applies_to: {}'.format(applies_to))
        return applies_to


class RuleMode(object):
    """The rule mode."""

    WHITELIST = 'whitelist'
    BLACKLIST = 'blacklist'
    REQUIRED = 'required'

    modes = frozenset([WHITELIST, BLACKLIST, REQUIRED])

    @classmethod
    def verify(cls, mode):
        """Verify whether the mode is valid."""
        if mode not in cls.modes:
            raise InvalidRulesSchemaError(
                'Invalid rule mode: {}'.format(mode))
        return mode


class OrgRuleBook(BaseRuleBook):
    """The RuleBook for organization resources.

    Rules from the rules definition file are parsed and placed into a
    map, which associates the GCP resource with the particular rules
    defined for it.

    Sample rules (simplified):

    mode: whitelist
    Org 1234, bindings: roles/*, members: user:*@company.com
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

    def __init__(self, rule_defs=None, verify_resource_exists=False):
        """Initialize.

        Args:
            rule_defs: The parsed dictionary of rules from the YAML
                       definition file.
        """
        super(OrgRuleBook, self).__init__(logger_name=__name__)
        self._lock = threading.Lock()
        self.resource_rules_map = {}
        self.verify_resource_exists = verify_resource_exists
        if not rule_defs:
            self.rule_defs = {}
        else:
            self.rule_defs = rule_defs
            self.add_rules(rule_defs)

    def __eq__(self, other):
        if not isinstance(other, type(self)):
            return NotImplemented
        return self.resource_rules_map == other.resource_rules_map

    def __ne__(self, other):
        return not self == other

    def __repr__(self):
        return 'OrgRuleBook <{}>'.format(self.resource_rules_map)

    def add_rules(self, rule_defs):
        """Add rules to the rule book.

        Args:
            rule_defs: The parsed dictionary of rules from the YAML
                       definition file.
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
            rule_def: A dictionary containing rule definition properties.
            rule_index: The index of the rule from the rule definitions.
                Assigned automatically when the rule book is built.
        """
        with self._lock:
            resources = rule_def.get('resource')

            for resource in resources:
                resource_ids = resource.get('resource_ids')
                resource_type = None
                # TODO: collect these errors and output them in a log.
                # Question: should we ever fail fast? I'm thinking "no"
                # since we still want to try and run as many rules as
                # possible.
                try:
                    resource_type = ResourceType.verify(resource.get('type'))
                except InvalidResourceTypeError:
                    raise InvalidRulesSchemaError(
                        'Missing resource type in rule {}'.format(rule_index))

                if not resource_ids or len(resource_ids) < 1:
                    raise InvalidRulesSchemaError(
                        'Missing resource ids in rule {}'.format(rule_index))

                # For each resource id associated with the rule, create a
                # mapping of resource => rules.
                for resource_id in resource_ids:
                    gcp_resource = ResourceUtil.create_resource(
                        resource_id=resource_id,
                        resource_type=resource_type)
                    # Verify that this resource actually exists in GCP.
                    if (self.verify_resource_exists and
                            not gcp_resource.exists()):

                        self.logger.error('Resource does not exist: %s',
                                          gcp_resource)
                        continue

                    rule = Rule(rule_name=rule_def.get('name'),
                                rule_index=rule_index,
                                bindings=rule_def.get('bindings', []),
                                mode=rule_def.get('mode'))

                    # See if we have a mapping of the resource and rule
                    resource_rules = self.resource_rules_map.get(gcp_resource)

                    # If no mapping exists, create it.
                    if not resource_rules:
                        resource_rules = ResourceRules(
                            resource=gcp_resource,
                            applies_to=resource.get('applies_to'),
                            inherit_from_parents=rule_def.get(
                                'inherit_from_parents', False))
                        self.resource_rules_map[gcp_resource] = resource_rules

                    # If the rule isn't in the mapping, add it.
                    if rule not in resource_rules.rules:
                        resource_rules.rules.add(rule)

    def find_violations(self, resource, policy_binding):
        """Find policy binding violations in the rule book.

        Args:
            resource: The GCP resource associated with the policy binding.
                This is where we start looking for rule violations and
                we move up the resource hierarchy (if permitted by the
                resource's "inherit_from_parents" property).
            policy_binding: An IamPolicyBinding.

        Returns:
            A generator of the rule violations.
        """
        violations = []
        for curr_resource in resource.get_ancestors():
            resource_rules = self.resource_rules_map.get(curr_resource)

            if not resource_rules:
                continue

            # Check whether rules match if the applies_to condition is met:
            # SELF: check rules if the starting resource == current resource
            # CHILDREN: check rules if starting resource != current resource
            # SELF_AND_CHILDREN: always check rules
            do_rules_check = (
                (resource_rules.applies_to == RuleAppliesTo.SELF and
                 resource == curr_resource) or
                (resource_rules.applies_to == RuleAppliesTo.CHILDREN and
                 resource != curr_resource) or
                (resource_rules.applies_to == RuleAppliesTo.SELF_AND_CHILDREN))

            if not do_rules_check:
                continue

            # pylint: disable=redefined-variable-type
            violations = itertools.chain(
                violations,
                resource_rules.find_mismatches(resource, policy_binding))

            # If the rule does not inherit the parents' rules, stop.
            if not resource_rules.inherit_from_parents:
                break
        return violations


class ResourceRules(object):
    """An association of a resource to rules."""

    def __init__(self,
                 resource=None,
                 rules=None,
                 applies_to=RuleAppliesTo.SELF,
                 inherit_from_parents=False):
        """Initialize.

        Args:
            resource: The resource to associate with the rule.
            rules: A set with rules to associate with the resource.
            applies_to: Whether the rule applies to the resource's
                self, children, or both.
            inherit_from_parents: Whether the rule lookup should request
                the resource's ancestor's rules.
        """
        if not isinstance(rules, set):
            rules = set([])
        self.resource = resource
        self.rules = rules
        self.applies_to = applies_to
        self.inherit_from_parents = inherit_from_parents

        self._rule_mode_methods = {
            RuleMode.WHITELIST: self._whitelist_member_check,
            RuleMode.BLACKLIST: self._blacklist_member_check,
            RuleMode.REQUIRED: self._required_member_check,
        }

    def __eq__(self, other):
        if not isinstance(other, type(self)):
            return NotImplemented
        return (self.resource == other.resource and
                self.rules == other.rules and
                self.applies_to == other.applies_to and
                self.inherit_from_parents == other.inherit_from_parents)

    def __ne__(self, other):
        return not self == other

    def __repr__(self):
        """String representation of this node."""
        return ('ResourceRules<resource={}, rules={}, '
                'applies_to={}, inherit_from_parents={}>').format(
                    self.resource, self.rules, self.applies_to,
                    self.inherit_from_parents)

    def find_mismatches(self, policy_resource, binding_to_match):
        """Determine if the policy binding matches this rule's criteria.

        How the member matching operates:

        1. Whitelist: policy members match at least one rule member
        2. Blacklist: policy members must not match any rule members
        3. Require: rule members must all match policy members

        Args:
            policy_resource: The resource that the policy belongs to.
            binding_to_match: The IamPolicyBinding binding to compare to
                this rule's bindings.

        Returns:
            A generator of RuleViolations.
        """
        policy_binding = IamPolicyBinding.create_from(binding_to_match)

        for rule in self.rules:
            # TODO: transform the policy binding into a {role: members} dict
            found_role = False
            for binding in rule.bindings:
                policy_role_name = policy_binding.role_name
                if not policy_binding.role_name.startswith('roles'):
                    policy_role_name = 'roles/{}'.format(
                        policy_binding.role_name)

                # If the rule's role pattern matches the policy binding's role
                # pattern, then check the members to see whether they match,
                # according to the rule mode.
                if binding.role_pattern.match(policy_role_name):
                    if rule.mode == RuleMode.REQUIRED:
                        role_name = binding.role_name
                    else:
                        role_name = policy_role_name
                    found_role = True
                    violating_members = (self._dispatch_rule_mode_check(
                        mode=rule.mode,
                        rule_members=binding.members,
                        policy_members=policy_binding.members))
                    if violating_members:
                        yield RuleViolation(
                            resource_type=policy_resource.resource_type,
                            resource_id=policy_resource.resource_id,
                            rule_name=rule.rule_name,
                            rule_index=rule.rule_index,
                            violation_type=RULE_VIOLATION_TYPE.get(
                                rule.mode, RULE_VIOLATION_TYPE['UNSPECIFIED']),
                            role=role_name,
                            members=violating_members)

            # Extra check if the role did not match in the REQUIRED case.
            if not found_role and rule.mode == RuleMode.REQUIRED:
                for binding in rule.bindings:
                    yield RuleViolation(
                        resource_type=policy_resource.resource_type,
                        resource_id=policy_resource.resource_id,
                        rule_name=rule.rule_name,
                        rule_index=rule.rule_index,
                        violation_type=RULE_VIOLATION_TYPE.get(
                            rule.mode, RULE_VIOLATION_TYPE['UNSPECIFIED']),
                        role=binding.role_name,
                        members=binding.members)

    def _dispatch_rule_mode_check(self, mode, rule_members=None,
                                  policy_members=None):
        """Determine which rule mode method to execute for rule audit.

        Args:
            rule_members: The list of rule binding members.
            policy_members: The list of policy binding members.

        Returns:
            The result of calling the dispatched method.
        """
        return self._rule_mode_methods[mode](
            rule_members=rule_members,
            policy_members=policy_members)

    # TODO: Investigate making a function, not a method.
    # pylint: disable=no-self-use
    def _whitelist_member_check(self, rule_members=None,
                                policy_members=None):
        """Whitelist: Check that policy members ARE in rule members.

        If a policy member is NOT found in the rule members, add it to
        the violating members.

        Args:
            rule_members: A list of IamPolicyMembers allowed in the rule.
            policy_members: A list of IamPolicyMembers in the policy.

        Return:
            A list of the violating members: policy members NOT found in
            the whitelist (rule members).
        """
        violating_members = []
        for policy_member in policy_members:
            found_in_rules = False
            for rule_member in rule_members:
                found_in_rules = rule_member.matches(policy_member)
                if found_in_rules:
                    break
            if not found_in_rules:
                violating_members.append(policy_member)
        return violating_members

    # TODO: Investigate making a function, not a method.
    # pylint: disable=no-self-use
    def _blacklist_member_check(self, rule_members=None,
                                policy_members=None):
        """Blacklist: Check that policy members ARE NOT in rule members.

        If a policy member is found in the rule members, add it to the
        violating members.

        Args:
            rule_members: A list of IamPolicyMembers allowed in the rule.
            policy_members: A list of IamPolicyMembers in the policy.

        Return:
            A list of the violating members: policy members found in
            the blacklist (rule members).
        """
        violating_members = []
        for policy_member in policy_members:
            for rule_member in rule_members:
                if rule_member.matches(policy_member):
                    violating_members.append(policy_member)
                    break
        return violating_members

    # TODO: Investigate making a function, not a method.
    # pylint: disable=no-self-use
    def _required_member_check(self, rule_members=None,
                               policy_members=None):
        """Required: Check that rule members are in policy members.

        If a required rule member is NOT found in the policy members, add
        it to the violating members. Note that the check is different:
        it's reversed from the whitelist/blacklist (policy as a subset of
        rules vs rules as subset of policy).

        Args:
            rule_members: A list of IamPolicyMembers allowed in the rule.
            policy_members: A list of IamPolicyMembers in the policy.

        Return:
            A list of the violating members: rule members not found in the
            policy (required-whitelist).
        """
        violating_members = []
        for rule_member in rule_members:
            found_in_rules = False
            for policy_member in policy_members:
                found_in_rules = rule_member.matches(policy_member)
                if found_in_rules:
                    break
            if not found_in_rules:
                violating_members.append(rule_member)
        return violating_members


# pylint: disable=too-few-public-methods
class Rule(object):
    """Encapsulate Rule properties from the rule definition file.

    The reason this is not a named tuple is that it needs to be hashable.
    The ResourceRules class has a set of Rules.
    """

    def __init__(self, rule_name, rule_index, bindings, mode=None):
        """Initialize.

        Args:
            rule_name: The string name of the rule.
            rule_index: The rule's index in the rules file.
            bindings: The list of IamPolicyBindings for this rule.
            mode: The RulesMode for this rule.
        """
        self.rule_name = rule_name
        self.rule_index = rule_index
        self.bindings = self._get_bindings(bindings)
        self.mode = RuleMode.verify(mode)

    def __eq__(self, other):
        """Test whether Rule equals other Rule."""
        if not isinstance(other, type(self)):
            return NotImplemented
        return (self.rule_name == other.rule_name and
                self.rule_index == other.rule_index and
                self.bindings == other.bindings and
                self.mode == other.mode)

    def __ne__(self, other):
        """Test whether Rule is not equal to another Rule."""
        return not self == other

    def __hash__(self):
        """Make a hash of the rule index.

        For now, this will suffice since the rule index is assigned
        automatically when the rules map is built, and the scanner
        only handles one rule file at a time. Later on, we'll need to
        revisit this hash method when we process multiple rule files.

        Returns:
            The hash of the rule index.
        """
        return hash(self.rule_index)

    # TODO: Investigate making a function, not a method.
    # pylint: disable=no-self-use
    def __repr__(self):
        """Returns the string representation of this Rule."""
        return 'Rule <{}, name={}, mode={}, bindings={}>'.format(
            self.rule_index, self.rule_name, self.mode, self.bindings)

    def _get_bindings(self, bindings):
        """Get a list of this Rule's bindings as IamPolicyBindings.

        Args:
            bindings: A list of bindings (dict).

        Returns:
            A list of IamPolicyBindings.
        """
        return [IamPolicyBinding.create_from(b) for b in bindings]


# Rule violation.
RuleViolation = namedtuple('RuleViolation',
                           ['resource_type', 'resource_id', 'rule_name',
                            'rule_index', 'violation_type', 'role', 'members'])

# Rule violation types.
RULE_VIOLATION_TYPE = {
    'whitelist': 'ADDED',
    'blacklist': 'ADDED',
    'required': 'REMOVED',
    'UNSPECIFIED': 'UNSPECIFIED'
}
