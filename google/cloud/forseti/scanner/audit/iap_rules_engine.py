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
"""Rules engine for IAP policies on backend services."""
from collections import namedtuple
import re
import threading

from google.cloud.forseti.common.gcp_type import errors as resource_errors
from google.cloud.forseti.common.gcp_type import resource as resource_mod
from google.cloud.forseti.common.gcp_type import resource_util
from google.cloud.forseti.common.util import logger
from google.cloud.forseti.common.util import regular_exp
from google.cloud.forseti.scanner.audit import base_rules_engine as bre
from google.cloud.forseti.scanner.audit import errors as audit_errors
from google.cloud.forseti.scanner.audit import rules as scanner_rules

LOGGER = logger.get_logger(__name__)


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

    def find_violations(self, iap_resource):
        """Determine whether IAP-related settings violate rules.

        Args:
            iap_resource (IapResource): IAP resource data

        Returns:
            list: RuleViolation
        """
        if self.rule_book is None:
            self.build_rule_book()
        return self.rule_book.find_violations(iap_resource)
    # pylint: enable=arguments-differ

    def add_rules(self, rules):
        """Add rules to the rule book.

        Args:
            rules (list): dicts defining the rules to add
        """
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
        del global_configs
        self._rules_sema = threading.BoundedSemaphore(value=1)
        self.resource_rules_map = {}
        if not rule_defs:
            self.rule_defs = {}
        else:
            self.rule_defs = rule_defs
            self.add_rules(rule_defs)
        self.snapshot_timestamp = snapshot_timestamp

    def add_rules(self, rule_defs):
        """Add rules to the rule book.

        Args:
            rule_defs (list): rule definition property dicts
        """
        for (i, rule) in enumerate(rule_defs.get('rules', [])):
            self.add_rule(rule, i)

    def add_rule(self, rule_def, rule_index):  # pylint: disable=too-many-locals
        """Add a rule to the rule book.

        Args:
            rule_def (dict): rule definition properties
            rule_index (int): index of the rule from the rule definitions,
                              assigned automatically when the rule book is built
        """
        self._rules_sema.acquire()

        try:
            for resource in rule_def.get('resource'):
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

                allowed_alternate_services = [
                    regular_exp.escape_and_globify(glob)
                    for glob in rule_def.get(
                        'allowed_alternate_services', '').split(',')
                    if glob]
                allowed_direct_access_sources = [
                    regular_exp.escape_and_globify(glob)
                    for glob in rule_def.get(
                        'allowed_direct_access_sources', '').split(',')
                    if glob]
                allowed_iap_enabled = regular_exp.escape_and_globify(
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
                        allowed_direct_access_sources=(
                            allowed_direct_access_sources),
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
        finally:
            self._rules_sema.release()

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

    def find_violations(self, iap_resource):
        """Find violations in the rule book.

        Args:
            iap_resource (IapResource): IAP data

        Returns:
            list: RuleViolation
        """
        LOGGER.debug('Looking for IAP violations: %r', iap_resource)
        violations = []
        resource = iap_resource.backend_service

        resource_ancestors = resource_util.get_ancestors_from_full_name(
            iap_resource.project_full_name)

        LOGGER.debug('Ancestors of resource: %r', resource_ancestors)

        for curr_resource in resource_ancestors:
            wildcard_resource = resource_util.create_resource(
                resource_id='*', resource_type=curr_resource.type)
            resource_rules = self.get_resource_rules(curr_resource)
            resource_rules.extend(self.get_resource_rules(wildcard_resource))

            LOGGER.debug('Resource rules for %r: %r', curr_resource,
                         resource_rules)
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

                LOGGER.debug('Does %r apply to resource? %r',
                             resource_rule,
                             rule_applies_to_resource)
                if not rule_applies_to_resource:
                    continue

                violations.extend(
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

        LOGGER.debug('Returning violations: %r', violations)
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
            applies_to (RuleAppliesTo): Whether the rule applies to the
                resource's self, children, or both.
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
            list: RuleViolation
        """
        violations = []
        for rule in self.rules:
            violation = rule.find_mismatches(resource, iap_resource)
            if violation:
                violations.append(violation)
        return violations

    def __eq__(self, other):
        """Compare == with another object.

        Args:
            other (ResourceRules): object to compare with

        Returns:
            int: comparison result
        """
        if not isinstance(other, type(self)):
            return NotImplemented
        return (self.resource == other.resource and
                self.rules == other.rules and
                self.applies_to == other.applies_to and
                self.inherit_from_parents == other.inherit_from_parents)

    def __ne__(self, other):
        """Compare != with another object.

        Args:
            other (object): object to compare with

        Returns:
            int: comparison result
        """
        return not self == other

    def __repr__(self):
        """String representation of this node.

        Returns:
            str: debug string
        """
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
                to this service's backends, without going through the load
                balancer.
            allowed_iap_enabled (str): Regex string describing allowed values
                for "IAP enabled" setting on this service.
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

        Returns:
            RuleViolation: IAP violations
        """
        LOGGER.debug('Has enabled violation? %r / %r',
                     self.allowed_iap_enabled,
                     iap_resource.iap_enabled)
        if self.allowed_iap_enabled != '^.+$':
            iap_enabled_regex = re.compile(
                self.allowed_iap_enabled)
            iap_enabled_violation = not iap_enabled_regex.match(
                str(iap_resource.iap_enabled))
        else:
            iap_enabled_violation = False
        LOGGER.debug('Enabled violation: %r', iap_enabled_violation)

        LOGGER.debug('Has alternate service violation? %r / %r / %r',
                     iap_resource.iap_enabled,
                     self.allowed_alternate_services,
                     iap_resource.alternate_services)
        if iap_resource.iap_enabled:
            alternate_services_regexes = [
                re.compile(regex) for regex in self.allowed_alternate_services]
            alternate_services_violations = [
                service for service in iap_resource.alternate_services
                if not [regex for regex in alternate_services_regexes
                        if regex.match(service.name)]
            ]
        else:
            alternate_services_violations = []
        LOGGER.debug('Alternate services violations: %r',
                     alternate_services_violations)

        LOGGER.debug('Has sources violation? %r / %r / %r',
                     iap_resource.iap_enabled,
                     self.allowed_direct_access_sources,
                     iap_resource.direct_access_sources)
        if iap_resource.iap_enabled:
            sources_regexes = [
                re.compile(regex)
                for regex in self.allowed_direct_access_sources]
            direct_sources_violations = [
                source for source in iap_resource.direct_access_sources
                if not [regex for regex in sources_regexes
                        if regex.match(source)]
            ]
        else:
            direct_sources_violations = []
        LOGGER.debug('Sources violations: %r', direct_sources_violations)

        should_raise_violation = (
            alternate_services_violations or
            iap_enabled_violation or
            direct_sources_violations)

        if should_raise_violation:
            return RuleViolation(
                resource_type=resource_mod.ResourceType.BACKEND_SERVICE,
                resource_name=resource.name,
                resource_id=resource.resource_id,
                full_name=resource.full_name,
                rule_name=self.rule_name,
                rule_index=self.rule_index,
                violation_type='IAP_VIOLATION',
                alternate_services_violations=alternate_services_violations,
                iap_enabled_violation=iap_enabled_violation,
                direct_access_sources_violations=(
                    direct_sources_violations),
                resource_data=resource.json)
        return None

    def __repr__(self):
        """String representation of this node.

        Returns:
            str: debug string
        """
        return ('IapRule<rule_name={}, rule_index={}, '
                'allowed_alternate_services={}, '
                'allowed_direct_access_sources={}, '
                'allowed_iap_enabled={}>').format(
                    self.rule_name, self.rule_index,
                    self.allowed_alternate_services,
                    self.allowed_direct_access_sources,
                    self.allowed_iap_enabled)

    def __eq__(self, other):
        """Test whether Rule equals other Rule.

        Args:
            other (Rule): object to compare to

        Returns:
            int: comparison result
        """
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
        """Test whether Rule is not equal to another Rule.

        Args:
            other (object): object to compare to

        Returns:
            int: comparison result
        """
        return not self == other

    def __hash__(self):
        """Make a hash of the rule index.

        For now, this will suffice since the rule index is assigned
        automatically when the rules map is built, and the scanner
        only handles one rule file at a time. Later on, we'll need to
        revisit this hash method when we process multiple rule files.

        Returns:
            int: The hash of the rule index.
        """
        return hash(self.rule_index)


RuleViolation = namedtuple(
    'RuleViolation',
    ['resource_type', 'resource_id', 'full_name', 'resource_name', 'rule_name',
     'rule_index', 'violation_type', 'alternate_services_violations',
     'iap_enabled_violation', 'direct_access_sources_violations',
     'resource_data'])
