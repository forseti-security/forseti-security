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

"""Rules engine for checking arbitrary properties ofKE clusters."""

from collections import namedtuple
import threading

import jmespath

from google.cloud.forseti.common.gcp_type import errors as resource_errors
from google.cloud.forseti.common.gcp_type import resource as resource_mod
from google.cloud.forseti.common.gcp_type import resource_util
from google.cloud.forseti.common.util import logger
from google.cloud.forseti.scanner.audit import base_rules_engine as bre
from google.cloud.forseti.scanner.audit import errors as audit_errors

LOGGER = logger.get_logger(__name__)


class KeRulesEngine(bre.BaseRulesEngine):
    """Rules engine for KE scanner."""

    def __init__(self, rules_file_path, snapshot_timestamp=None):
        """Initialize.

        Args:
            rules_file_path (str): file location of rules
            snapshot_timestamp (str): snapshot timestamp. Defaults to None.
                If set, this will be the snapshot timestamp
                used in the engine.
        """
        super(KeRulesEngine,
              self).__init__(rules_file_path=rules_file_path)
        self.rule_book = None
        self.snapshot_timestamp = snapshot_timestamp
        self._lock = threading.Lock()

    def build_rule_book(self, global_configs=None):
        """Build KeRuleBook from the rules definition file.

        Args:
            global_configs (dict): Global configurations.
        """
        with self._lock:
            self.rule_book = KeRuleBook(
                self._load_rule_definitions())

    def find_violations(self, ke_cluster, force_rebuild=False):
        """Check if KE cluster satisfies provided  rules.

        Args:
            ke_cluster (KeCluster): A KE Cluster object to check.
            force_rebuild (bool): If True, rebuilds the rule book. This will
                reload the rules definition file and add the rules to the book.

        Returns:
             generator: A generator of rule violations.
        """
        if self.rule_book is None or force_rebuild:
            self.build_rule_book()
        return self.rule_book.find_violations(ke_cluster)


class KeRuleBook(bre.BaseRuleBook):
    """The RuleBook for KE rules."""

    def __init__(self, rule_defs=None):
        """Initialization.

        Args:
            rule_defs (list): KE rule definition dicts
        """
        super(KeRuleBook, self).__init__()
        self._lock = threading.Lock()
        self.resource_rules_map = {}
        if not rule_defs:
            self.rule_defs = {}
        else:
            self.rule_defs = rule_defs
            self.add_rules(rule_defs)

    def add_rules(self, rule_defs):
        """Add rules to the rule book.

        Args:
            rule_defs (dict): rule definitions dictionary
        """
        for (i, rule) in enumerate(rule_defs.get('rules', [])):
            self.add_rule(rule, i)

    def add_rule(self, rule_def, rule_index):
        """Add a rule to the rule book.

        Args:
            rule_def (dict): A dictionary containing rule definition
                properties.
            rule_index (int): The index of the rule from the rule definitions.
                Assigned automatically when the rule book is built.
        """
        with self._lock:
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

                rule_mode = rule_def.get('mode')
                if rule_mode not in ('blacklist', 'whitelist'):
                    raise audit_errors.InvalidRulesSchemaError(
                        'Unknown mode in rule {}'.format(rule_index))

                rule_key = rule_def.get('key')
                if rule_key is None:
                    raise audit_errors.InvalidRulesSchemaError(
                        'Missing key in rule {}'.format(rule_index))

                rule_values = rule_def.get('values', [])

                # For each resource id associated with the rule, create a
                # mapping of resource => rules.
                for resource_id in resource_ids:
                    gcp_resource = resource_util.create_resource(
                        resource_id=resource_id,
                        resource_type=resource_type)

                    rule = Rule(
                        rule_def.get('name'),
                        rule_index,
                        rule_mode,
                        rule_key,
                        rule_values,
                    )
                    resource_rules = self.resource_rules_map.setdefault(
                        gcp_resource, ResourceRules(resource=gcp_resource))

                    if rule not in resource_rules.rules:
                        resource_rules.rules.add(rule)

    # pylint: enable=invalid-name

    def get_resource_rules(self, resource):
        """Get all the resource rules for resource.

        Args:
            resource (Resource): The gcp_type Resource find in the map.

        Returns:
            ResourceRules: A ResourceRules object.
        """
        return self.resource_rules_map.get(resource)

    def find_violations(self, ke_cluster):
        """Find violations in the rule book.

        Args:
            ke_cluster (KeCluster): KE Cluster and ServerConfig data.

        Returns:
            list: RuleViolation
        """
        LOGGER.debug('Looking for KE violations: %r', ke_cluster)
        violations = []
        resource_ancestors = resource_util.get_ancestors_from_full_name(
            ke_cluster.full_name)

        LOGGER.debug('Ancestors of resource: %r', resource_ancestors)

        checked_wildcards = set()
        for curr_resource in resource_ancestors:
            if not curr_resource:
                # resource_ancestors will contain all the resources including
                # the child resource, which has type kubernetes cluster and
                # cannot be created (return None) as part of the ancestor path,
                # we will skip the child as it's not part of the ancestor.
                continue

            resource_rules = self.get_resource_rules(curr_resource)
            if resource_rules:
                violations.extend(
                    resource_rules.find_violations(ke_cluster))

            wildcard_resource = resource_util.create_resource(
                resource_id='*', resource_type=curr_resource.type)
            if wildcard_resource in checked_wildcards:
                continue
            checked_wildcards.add(wildcard_resource)
            resource_rules = self.get_resource_rules(wildcard_resource)
            if resource_rules:
                violations.extend(
                    resource_rules.find_violations(ke_cluster))

        LOGGER.debug('Returning violations: %r', violations)
        return violations


class ResourceRules(object):
    """An association of a resource to rules."""

    def __init__(self,
                 resource=None,
                 rules=None):
        """Initialize.

        Args:
            resource (Resource): The resource to associate with the rule.
            rules (set): rules to associate with the resource.
        """
        if not isinstance(rules, set):
            rules = set([])
        self.resource = resource
        self.rules = rules

    def find_violations(self, ke_cluster):
        """Determine if the policy binding matches this rule's criteria.

        Args:
            ke_cluster (KeCluster): KE Cluster and ServerConfig data.

        Returns:
            list: RuleViolation
        """
        violations = []
        for rule in self.rules:
            rule_violations = rule.find_violations(ke_cluster)
            if rule_violations:
                violations.extend(rule_violations)
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
                self.rules == other.rules)

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
        return 'IapResourceRules<resource={}, rules={}>'.format(
            self.resource, self.rules)


class Rule(object):
    """Rule properties from the rule definition file, also finds violations."""

    def __init__(self, rule_name, rule_index, rule_mode, rule_key, rule_values):
        """Initialize.

        Args:
            rule_name (str): Name of the loaded rule
            rule_index (int): The index of the rule from the rule definitions
            rule_mode (str): blacklist or whitelist
            rule_key (str): jmespath pointing to the desired key
            rule_values (list): list of values, interpreted per mode
        """
        self.rule_name = rule_name
        self.rule_index = rule_index
        self.rule_mode = rule_mode
        self.rule_key = rule_key
        self.rule_values = rule_values

        # compile right away to return exceptions asap
        self.rule_jmespath = jmespath.compile(self.rule_key)

    def find_violations(self, ke_cluster):
        """Find KE violations in based on the rule.

        Args:
            ke_cluster (KeCluster): KE Cluster and ServerConfig data.

        Returns:
            list: Returns a list of RuleViolation named tuples
        """
        violations = []

        actual = self.rule_jmespath.search(ke_cluster.as_dict)
        LOGGER.debug('actual jmespath result: %s', actual)

        if self.rule_mode == 'whitelist':
            if actual not in self.rule_values:
                violations.append(self._make_violation(
                    ke_cluster,
                    '%s has value %s, which is not in the whitelist (%s)' % (
                        self.rule_jmespath.expression,
                        actual,
                        self.rule_values,
                    ),
                    actual,
                ))

        if self.rule_mode == 'blacklist':
            if actual in self.rule_values:
                violations.append(self._make_violation(
                    ke_cluster,
                    '%s has value %s, which is in the blacklist (%s)' % (
                        self.rule_jmespath.expression,
                        actual,
                        self.rule_values,
                    ),
                    actual,
                ))

        return violations

    def _make_violation(self, ke_cluster, violation_reason, actual):
        """Build a RuleViolation for the cluster.

        Args:
            ke_cluster (KeCluster): KE Cluster and ServerConfig data.
            violation_reason (str): The violation details.
            actual (object): The actual value of the jmespath expression.

        Returns:
            RuleViolation: A new RuleViolation namedtuple.
        """
        return RuleViolation(
            resource_type=resource_mod.ResourceType.KE_CLUSTER,
            resource_id=ke_cluster.name,
            full_name=ke_cluster.full_name,
            rule_name=self.rule_name,
            rule_index=self.rule_index,
            rule_mode=self.rule_mode,
            rule_values=self.rule_values,
            actual_value=actual,
            violation_type='KE_VIOLATION',
            violation_reason=violation_reason,
            project_id=ke_cluster.parent.id,
            cluster_name=ke_cluster.name,
            resource_data=ke_cluster.data,
            resource_name=ke_cluster.name,
        )

    def __eq__(self, other):
        """Test whether Rule equals other Rule.

        Args:
            other (Rule): object to compare to

        Returns:
            int: comparison result
        """
        if not isinstance(other, type(self)):
            return NotImplemented
        return all(
            self.rule_name == other.rule_name,
            self.rule_index == other.rule_index,
            self.rule_mode == other.rule_mode,
            self.rule_values == other.rule_values,
        )

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


# pylint: enable=inconsistent-return-statements

# Rule violation.
# resource_type: string
# resource_id: string
# rule_name: string
# rule_index: int
# violation_type: KE_VIOLATION
# violation_reason: string
# project_id: string
# cluster_name: string
RuleViolation = namedtuple('RuleViolation', [
    'resource_type',
    'resource_id',
    'full_name',
    'rule_name',
    'rule_index',
    'rule_mode',
    'rule_values',
    'actual_value',
    'violation_type',
    'violation_reason',
    'project_id',
    'cluster_name',
    'resource_data',
    'resource_name',
])
