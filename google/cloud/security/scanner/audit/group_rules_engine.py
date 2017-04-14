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

"""Rules engine for Google Groups.

1. Build the RuleBook (GroupRuleBook) from the rule definitions (file either
   stored locally or in GCS).
2. Get the GCP groups data.
3. Compare the GCP groups data against the RuleBook to determine whether there
   are violations.
"""
# pylint: disable=unused-argument
# pylint: disable=abstract-method
# pylint: disable=too-many-locals
# pylint: disable=too-few-public-methods
# pylint: disable=duplicate-code

from google.cloud.security.common.gcp_type import errors as resource_errors
from google.cloud.security.common.gcp_type.resource import ResourceType
from google.cloud.security.common.gcp_type.group_member import GroupMember
from google.cloud.security.common.gcp_type.resource_util import ResourceUtil
from google.cloud.security.common.util import log_util
from google.cloud.security.scanner.audit import base_rules_engine as bre
from google.cloud.security.scanner.audit import errors as audit_errors


LOGGER = log_util.get_logger(__name__)


def _check_whitelist_members(rule_members=None, group_members=None):
    """Whitelist: Check that group members ARE in rule members.

    If a group member is NOT found in the rule members, add it to
    the violating members.

    Args:
        rule_members: A list of Group Members allowed in the rule.
        group_members: A list of Group Members in the policy.

    Return:
        A list of the violating members: group members NOT found in
        the whitelist (rule members).
    """
    pass

def _check_blacklist_members(rule_members=None, group_members=None):
    """Blacklist: Check that group members ARE NOT in rule members.

    If a group member is found in the rule members, add it to the
    violating members.

    Args:
        rule_members: A list of Group Members allowed in the rule.
        group_members: A list of Group Members in the policy.

    Return:
        A list of the violating members: group members found in
        the blacklist (rule members).
    """
    pass

def _check_required_members(rule_members=None, group_members=None):
    """Required: Check that rule members are in group members.

    If a required rule member is NOT found in the group members, add
    it to the violating members. Note that the check is different:
    it's reversed from the whitelist/blacklist (policy as a subset of
    rules vs rules as subset of policy).

    Args:
        rule_members: A list of Group Members allowed in the rule.
        group_members: A list of Group Members in the policy.

    Return:
        A list of the violating members: rule members not found in the
        policy (required-whitelist).
    """
    pass


class GroupRulesEngine(bre.BaseRulesEngine):
    """Rules engine for group-related resources."""

    def __init__(self, rules_file_path):
        super(GroupRulesEngine, self).__init__(
            rules_file_path=rules_file_path)
        self.rule_book = GroupRuleBook(self._load_rule_definitions())


class GroupRuleBook(bre.BaseRuleBook):
    """The RuleBook for group resources."""

    def __init__(self, rule_defs=None, verify_resource_exists=False):
        """Initialize.

        Args:
            rule_defs: The parsed dictionary of rules from the YAML
                       definition file.
        """
        super(GroupRuleBook, self).__init__()
        self.resource_rules_map = {}
        self.verify_resource_exists = verify_resource_exists
        if not rule_defs:
            self.rule_defs = {}
        else:
            self.rule_defs = rule_defs
            self.add_rules(rule_defs)

    def add_rules(self, rule_defs):
        """Add rules."""
        for (i, rule) in enumerate(self.rule_defs.get('rules', [])):
            self.add_rule(rule, i)

    def add_rule(self, rule_def, rule_index):
        """Add rule to the rule book."""
        resources = rule_def.get('resource')

        for resource in resources:
            resource_ids = resource.get('resource_ids')

            try:
                resource_type = ResourceType.verify(resource.get('type'))
            except resource_errors.InvalidResourceTypeError:
                raise audit_errors.InvalidRulesSchemaError(
                    'Missing resource type in rule {}'.format(rule_index))

            if not resource_ids or len(resource_ids) < 1:
                raise audit_errors.InvalidRulesSchemaError(
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

                    LOGGER.error('Resource does not exist: %s',
                                 gcp_resource)
                    continue

                rule_members = []
                rule_def_members = rule_def.get('members')
                for rule_def_member in rule_def_members:
                    rule_members.append(GroupMember(rule_def_member))

                rule = Rule(rule_name=rule_def.get('name'),
                            rule_index=rule_index,
                            members=rule_members,
                            mode=rule_def.get('mode'))

                rule_applies_to = resource.get('applies_to')
                rule_key = (gcp_resource, rule_applies_to)

                # See if we have a mapping of the resource and rule
                resource_rules = self.resource_rules_map.get(
                    rule_key)

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



class Rule(object):
    """Encapsulate Rule properties from the rule definition file.

    The reason this is not a named tuple is that it needs to be hashable.
    The ResourceRules class has a set of Rules.
    """

    def __init__(self, rule_name, rule_index, members, mode=None):
        """Initialize.

        Args:
            rule_name: The string name of the rule.
            rule_index: The rule's index in the rules file.
            members: List of the rule members.
        """
        self.rule_name = rule_name
        self.rule_index = rule_index
        self.members = members


class ResourceRules(object):
    """An association of a resource to rules."""

    def __init__(self,
                 resource=None,
                 rules=None,
                 applies_to=bre.RuleAppliesTo.SELF,
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
        self.applies_to = bre.RuleAppliesTo.verify(applies_to)
        self.inherit_from_parents = inherit_from_parents

        self._rule_mode_methods = {
            bre.RuleMode.WHITELIST: _check_whitelist_members,
            bre.RuleMode.BLACKLIST: _check_blacklist_members,
            bre.RuleMode.REQUIRED: _check_required_members,
        }
