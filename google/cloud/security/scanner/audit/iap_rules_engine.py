
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

from google.cloud.security.common.data_access import org_resource_rel_dao
from google.cloud.security.common.gcp_type import errors as resource_errors
from google.cloud.security.common.gcp_type import resource as resource_mod
from google.cloud.security.common.gcp_type import resource_util
from google.cloud.security.common.util import log_util
from google.cloud.security.common.util import regex_util
from google.cloud.security.scanner.audit import base_rules_engine as bre
from google.cloud.security.scanner.audit import errors as audit_errors
from google.cloud.security.scanner.audit import rules as scanner_rules

LOGGER = log_util.get_logger(__name__)


# TODO: This duplicates a lot of resource-handling code from the IAM
# rules engine.


class IapRulesEngine(bre.BaseRulesEngine):
    """Rules engine for applying IAP policies to backend services"""

    def __init__(self, rules_file_path, snapshot_timestamp=None):
        """Initialize.

        Args:
            rules_file_path (str): file location of rules
            snapshot_timestamp (int): snapshot to load
        """
        super(IapRulesEngine,
              self).__init__(
                  rules_file_path=rules_file_path,
                  snapshot_timestamp=snapshot_timestamp)
        self.rule_book = None

    def build_rule_book(self, global_configs):
        """Build IapRuleBook from the rules definition file.

        Args:
            global_configs (dict): Global configurations.
        """
        self.rule_book = IapRuleBook(
            global_configs,
            self._load_rule_definitions(),
            snapshot_timestamp=self.snapshot_timestamp)

    def find_iap_violations(self, resource, iap_resource, force_rebuild=False):
        """Determine whether IAP-related settings violate rules.

        Args:
            resource (Resource): find violations on this
            iap_resource (IapResource): IAP resource data
            force_rebuild (bool): whether to rebuild the rulebook

        Returns:
            generator: Of RuleViolation
        """
        if self.rule_book is None or force_rebuild:
            self.build_rule_book()
        return self.rule_book.find_violations(resource, iap_resource)

    def add_rules(self, rules):
        """Add rules to the rule book.

        Args:
            rules (list): dicts defining the rules to add"""
        if self.rule_book is not None:
            self.rule_book.add_rules(rules)


class IapRuleBook(bre.BaseRuleBook):
    """The RuleBook for enforcing IAP policy on backend service resources."""

    def __init__(self, global_configs, rule_defs=None, snapshot_timestamp=None):
        """Initialization.

        Args:
            global_configs (dict): Global configurations.
            rule_defs (list): IAP rule definition dicts
            snapshot_timestamp (int): Snapshot timestamp.
        """
        super(IapRuleBook, self).__init__()
        self.resource_rules_map = {}
        if not rule_defs:
            self.rule_defs = {}
        else:
            self.rule_defs = rule_defs
            self.add_rules(rule_defs)
        if snapshot_timestamp:
            self.snapshot_timestamp = snapshot_timestamp
        self.org_res_rel_dao = org_resource_rel_dao.OrgResourceRelDao(
            global_configs)

    def add_rules(self, rule_defs):
        """Add rules to the rule book.

        Args:
            rule_defs (list): rule definition property dicts"""
        for (i, rule) in enumerate(rule_defs.get('rules', [])):
            self.add_rule(rule, i)

    def add_rule(self, rule_def, rule_index):
        """Add a rule to the rule book.

        Args:
            rule_def (dict): rule definition properties
            rule_index (int): index of the rule from the rule definitions,
                              assigned automatically when the rule book is built
        """

        resources = rule_def.get('resource')

        for resource in resources:
            resource_ids = resource.get('resource_ids')
            resource_type = None
            try:
                resource_type = resource_mod.ResourceType.verify(
                    resource.get('type'))
            except resource_errors.InvalidResourceTypeError:
                raise audit_errors.InvalidRulesSchemaError(
                    'Missing resource type in rule {}'.format(rule_index))

            if not resource_ids or len(resource_ids) < 1:
                raise audit_errors.InvalidRulesSchemaError(
                    'Missing resource ids in rule {}'.format(rule_index))

            allowed_alternate_services = regex_util.escape_and_globify(
                rule_def.get('allowed_alternate_services', ''))
            allowed_direct_access_sources = regex_util.escape_and_globify(
                rule_def.get('allowed_direct_access_sources', ''))
            allowed_iap_enabled = regex_util.escape_and_globify(
                rule_def.get('allowed_iap_enabled', '*'))

            # For each resource id associated with the rule, create a
            # mapping of resource => rules.
            for resource_id in resource_ids:
                gcp_resource = resource_util.create_resource(
                    resource_id=resource_id,
                    resource_type=resource_type)

                rule = Rule(
                    rule_name=rule_def.get('name'),
                    rule_index=rule_index,
                    allowed_alternate_services=allowed_alternate_services,
                    allowed_direct_access_sources=allowed_direct_access_sources,
                    allowed_iap_enabled=allowed_iap_enabled)

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

    def get_resource_rules(self, resource):
        """Get all the resource rules for (resource, RuleAppliesTo.*).

        Args:
            resource (Resource): The gcp_type Resource find in the map.

        Returns:
            list: ResourceRules
        """
        resource_rules = []

        for rule_applies_to in scanner_rules.RuleAppliesTo.apply_types:
            if (resource, rule_applies_to) in self.resource_rules_map:
                resource_rules.append(self.resource_rules_map.get(
                    (resource, rule_applies_to)))

        return resource_rules

    def find_violations(self, resource, iap_resource):
        """Find violations in the rule book.

        Args:

            resource (BackendService): The backend service to examine.
                This is where we start looking for rule violations and
                we move up the resource hierarchy (if permitted by the
                resource's "inherit_from_parents" property).
            iap_resource (IapResource): IAP data

        Returns:
            A generator of the rule violations.
        """
        violations = itertools.chain()
        resource_ancestors = [resource]
        resource_ancestors.extend(
            self.org_res_rel_dao.find_ancestors(
                resource, self.snapshot_timestamp))

        for curr_resource in resource_ancestors:
            resource_rules = self._get_resource_rules(curr_resource)
            # Set to None, because if the direct resource (e.g. project)
            # doesn't have a specific rule, we still should check the
            # ancestry to see if the resource's parents have any rules
            # that apply to the children.
            inherit_from_parents = None

            for resource_rule in resource_rules:
                # Check whether rules match if the applies_to condition is met:
                # SELF: check rules if the starting resource == current resource
                # CHILDREN: check rules if starting resource != current resource
                # SELF_AND_CHILDREN: always check rules
                applies_to_self = (
                    resource_rule.applies_to ==
                    scanner_rules.RuleAppliesTo.SELF and
                    resource == curr_resource)
                applies_to_children = (
                    resource_rule.applies_to ==
                    scanner_rules.RuleAppliesTo.CHILDREN and
                    resource != curr_resource)
                applies_to_both = (
                    resource_rule.applies_to ==
                    scanner_rules.RuleAppliesTo.SELF_AND_CHILDREN)

                rule_applies_to_resource = (
                    applies_to_self or
                    applies_to_children or
                    applies_to_both)

                if not rule_applies_to_resource:
                    continue

                violations = itertools.chain(
                    violations,
                    resource_rule.find_mismatches(resource, iap_resource))

                inherit_from_parents = resource_rule.inherit_from_parents

            # If the rule does not inherit the parents' rules, stop.
            # Due to the way rules are structured, we only define the
            # "inherit" property once per rule. So even though a rule
            # may apply to multiple resources, it will only have one
            # value for "inherit_from_parents".
            # TODO: Revisit to remove pylint disable
            # pylint: disable=compare-to-zero
            if inherit_from_parents is False:
                break
            # pylint: enable=compare-to-zero

        return violations


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
            rules (set): rules to associate with the resource.
            applies_to (RuleAppliesTo): Whether the rule applies to the resource's
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

    def find_mismatches(self, resource, iap_resource):
        """Determine if the policy binding matches this rule's criteria.

        Args:
            resource (Resource): Resource to evaluate
            iap_resource (IapResource): IAP data

        Returns:
            generator: RuleViolation
        """
        return itertools.chain(*[rule.find_mismatches(resource, iap_resource)
                                 for rule in self.rules])

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
        return ('IapResourceRules<resource={}, rules={}, '
                'applies_to={}, inherit_from_parents={}>').format(
                    self.resource, self.rules, self.applies_to,
                    self.inherit_from_parents)


class Rule(object):
    """Rule properties from the rule definition file.

    Also finds violations.
    """

    def __init__(self, rule_name, rule_index,
                 allowed_alternate_services,
                 allowed_direct_access_sources, allowed_iap_enabled):
        """Initialize.

        Args:
            rule_name (str): Name of the loaded rule
            rule_index (int): The index of the rule from the rule definitions
            allowed_alternate_services (str): Regex string describing backend
                services permitted to expose the same backends as this one.
            allowed_direct_access_sources (str): Regex string describing
                network origins (IPs and tags) allowed to connect directly
                to this service's backends, without going through the load balancer.
            allowed_iap_enabled (str): Regex string describing allowed values for
                "IAP enabled" setting on this service.
        """
        self.rule_name = rule_name
        self.rule_index = rule_index
        self.allowed_alternate_services = allowed_alternate_services
        self.allowed_direct_access_sources = allowed_direct_access_sources
        self.allowed_iap_enabled = allowed_iap_enabled

    def find_mismatches(self, resource, iap_resource):
        """Find IAP policy violations in the rule book.

        Args:
            resource (Resource): resource to inspect
            iap_resource (IapResource): IAP data

        Yields:
            RuleViolation: IAP violations
        """
        if self.allowed_iap_enabled != '^.+$':
            iap_enabled_regex = re.compile(
                self.allowed_iap_enabled)
            iap_enabled_violation = not iap_enabled_regex.match(
                str(iap_resource.iap_enabled))
        else:
            iap_enabled_violation = False

        if (iap_resource.iap_enabled and
                self.allowed_alternate_services != '^.+$'):
            alternate_services_regex = re.compile(
                self.allowed_alternate_services)
            alternate_services_violations = [
                service for service in iap_resource.alternate_services
                if not alternate_services_regex.match(service.name)
            ]
        else:
            alternate_services_violations = []

        if (iap_resource.iap_enabled and
                self.allowed_direct_access_sources != '^.+$'):
            sources_regex = re.compile(
                self.allowed_direct_access_sources)
            direct_sources_violations = [
                source for source in iap_resource.direct_access_sources
                if not sources_regex.match(source)
            ]
        else:
            direct_sources_violations = []

        should_raise_violation = (
            alternate_services_violations or
            iap_enabled_violation or
            direct_sources_violations)

        if should_raise_violation:
            yield RuleViolation(
                resource_type=resource.type,
                resource_id=resource.id,
                rule_name=self.rule_name,
                rule_index=self.rule_index,
                violation_type='IAP_VIOLATION',
                alternate_services_violations=alternate_services_violations,
                iap_enabled_violation=iap_enabled_violation,
                direct_access_sources_violations=(
                    direct_sources_violations))

    def __repr__(self):
        """String representation of this node."""
        return ('IapRule<rule_name={}, rule_index={}, '
                'allowed_alternate_services={}, '
                'allowed_direct_access_sources={}, '
                'allowed_iap_enabled={}>').format(
                    self.rule_name, self.rule_index,
                    self.allowed_alternate_services,
                    self.allowed_direct_access_sources,
                    self.allowed_iap_enabled)

    def __eq__(self, other):
        """Test whether Rule equals other Rule."""
        if not isinstance(other, type(self)):
            return NotImplemented
        return (self.rule_name == other.rule_name and
                self.rule_index == other.rule_index and
                (self.allowed_alternate_services ==
                 other.allowed_alternate_services) and
                (self.allowed_direct_access_sources ==
                 other.allowed_direct_access_sources) and
                self.allowed_iap_enabled == other.allowed_iap_enabled)

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


RuleViolation = namedtuple(
    'RuleViolation',
    ['resource_type', 'resource_id', 'rule_name',
     'rule_index', 'violation_type',
     'alternate_services_violations',
     'iap_enabled_violation', 'direct_access_sources_violations'])
