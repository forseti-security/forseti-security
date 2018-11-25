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
"""Rules engine for verifying KE Versions are allowed."""

from collections import namedtuple
import operator as op
import threading
from pkg_resources import parse_version

from google.cloud.forseti.common.gcp_type import errors as resource_errors
from google.cloud.forseti.common.gcp_type import resource as resource_mod
from google.cloud.forseti.common.gcp_type import resource_util
from google.cloud.forseti.common.util import logger
from google.cloud.forseti.scanner.audit import base_rules_engine as bre
from google.cloud.forseti.scanner.audit import errors as audit_errors

LOGGER = logger.get_logger(__name__)


class KeVersionRulesEngine(bre.BaseRulesEngine):
    """Rules engine for KE Version scanner."""

    def __init__(self, rules_file_path, snapshot_timestamp=None):
        """Initialize.

        Args:
            rules_file_path (str): file location of rules
            snapshot_timestamp (str): snapshot timestamp. Defaults to None.
                If set, this will be the snapshot timestamp
                used in the engine.
        """
        super(KeVersionRulesEngine,
              self).__init__(rules_file_path=rules_file_path)
        self.rule_book = None
        self.snapshot_timestamp = snapshot_timestamp
        self._lock = threading.Lock()

    def build_rule_book(self, global_configs=None):
        """Build KeVersionRuleBook from the rules definition file.

        Args:
            global_configs (dict): Global configurations.
        """
        with self._lock:
            self.rule_book = KeVersionRuleBook(
                self._load_rule_definitions())

    def find_violations(self, ke_cluster, force_rebuild=False):
        """Determine whether Kubernetes Engine cluster version violates rules.

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


class KeVersionRuleBook(bre.BaseRuleBook):
    """The RuleBook for KE Version rules."""

    def __init__(self, rule_defs=None):
        """Initialization.

        Args:
            rule_defs (list): KE Version rule definition dicts
        """
        super(KeVersionRuleBook, self).__init__()
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

    # pylint: disable=invalid-name
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

                check_serverconfig_valid_node_versions = rule_def.get(
                    'check_serverconfig_valid_node_versions', False)
                check_serverconfig_valid_master_versions = rule_def.get(
                    'check_serverconfig_valid_master_versions', False)
                allowed_nodepool_versions = rule_def.get(
                    'allowed_nodepool_versions', [])
                allowed_versions = []
                for allowed_version in allowed_nodepool_versions:
                    allowed_versions.append(VersionRule(**allowed_version))

                # For each resource id associated with the rule, create a
                # mapping of resource => rules.
                for resource_id in resource_ids:
                    gcp_resource = resource_util.create_resource(
                        resource_id=resource_id,
                        resource_type=resource_type)

                    rule = Rule(
                        rule_def.get('name'),
                        rule_index,
                        check_serverconfig_valid_node_versions,
                        check_serverconfig_valid_master_versions,
                        allowed_versions)

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
                # the child resource, which has type kebernete cluster and
                # cannot be created (return None) as part of the ancestor path,
                # we will skip the child as it's not part of the ancestor.
                continue

            resource_rule = self.get_resource_rules(curr_resource)
            if resource_rule:
                violations.extend(
                    resource_rule.find_violations(ke_cluster))

            wildcard_resource = resource_util.create_resource(
                resource_id='*', resource_type=curr_resource.type)
            if wildcard_resource in checked_wildcards:
                continue
            checked_wildcards.add(wildcard_resource)
            resource_rule = self.get_resource_rules(wildcard_resource)
            if resource_rule:
                violations.extend(
                    resource_rule.find_violations(ke_cluster))

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


class VersionRule(object):
    """Class to match allowed versions rules against running versions."""

    ALLOWED_OPERATORS = {'>': op.gt,
                         '<': op.lt,
                         '>=': op.ge,
                         '<=': op.le,
                         '=': op.eq}

    def __init__(self, major, minor=None, operator='='):
        """Initialize.

        Args:
            major (str): The major part of the Kubernetes version.
            minor (str): The minor part of the Kubernetes version.
            operator (str): The comparison operator.

        Raises:
            ValueError: Raised if operator is not an allowed value.
        """
        self._major = parse_version(major)
        if minor:
            self._minor = parse_version(minor)
        else:
            self._minor = None

        if operator not in self.ALLOWED_OPERATORS:
            raise ValueError('Operator %s not allowed.' % operator)

        self._operator_str = operator
        self._operator = self.ALLOWED_OPERATORS[operator]

    def __repr__(self):
        """Return string representation.

        Returns:
            str: String representation.
        """
        minor = self._minor if self._minor else '*'
        return '%s %s.%s' % (self._operator_str, self._major, minor)

    def __hash__(self):
        """Calculate hash.

        Returns:
            int: Unique hash.
        """
        return hash((self._major, self._minor, self._operator))

    def is_version_allowed(self, version):
        """Check if the version matches the allowed_version configuration.

        Args:
            version (str): A version string. e.g. '1.6.11.gke.1'

        Returns:
            bool: True if version is allowed, else False
        """
        LOGGER.debug('Checking version %s.', version)
        parts = version.split('.')
        major = parse_version('.'.join(parts[0:2]))
        minor = parse_version('.'.join(parts[2:]))

        if self._minor:
            if major != self._major:
                return False
            return self._operator(minor, self._minor)
        return self._operator(major, self._major)


# False positive - pylint: disable=inconsistent-return-statements
class Rule(object):
    """Rule properties from the rule definition file, also finds violations."""

    def __init__(self, rule_name, rule_index,
                 check_serverconfig_valid_node_versions,
                 check_serverconfig_valid_master_versions,
                 allowed_nodepool_versions):
        """Initialize.

        Args:
            rule_name (str): Name of the loaded rule
            rule_index (int): The index of the rule from the rule definitions
            check_serverconfig_valid_node_versions (bool): Check the node
                version is listed a supported version in the server config.
            check_serverconfig_valid_master_versions (bool): Check the master
                version is listed a supported version in the server config.
            allowed_nodepool_versions (list): A list of AllowedVersion tuples.
        """
        self.rule_name = rule_name
        self.rule_index = rule_index
        self.check_valid_node_versions = check_serverconfig_valid_node_versions
        self.check_valid_master_version = (
            check_serverconfig_valid_master_versions)
        self.allowed_versions = frozenset(allowed_nodepool_versions)

    def find_violations(self, ke_cluster):
        """Find KE Version violations in based on the rule.

        Args:
            ke_cluster (KeCluster): KE Cluster and ServerConfig data.

        Returns:
            list: Returns a list of RuleViolation named tuples
        """
        violations = []
        if self.check_valid_node_versions:
            violation = self._node_versions_valid(ke_cluster)
            if violation:
                violations.append(violation)

        if self.check_valid_master_version:
            violation = self._master_version_valid(ke_cluster)
            if violation:
                violations.append(violation)

        if self.allowed_versions:
            violation = self._node_versions_allowed(ke_cluster)
            if violation:
                violations.append(violation)
        return violations

    def _make_violation(self, ke_cluster, nodepool, violation_reason):
        """Build a RuleViolation for the cluster.

        Args:
            ke_cluster (KeCluster): KE Cluster and ServerConfig data.
            nodepool (dict): A node pool in the KE cluster.
            violation_reason (str): The violation details.

        Returns:
            RuleViolation: A new RuleViolation namedtuple.
        """
        node_pool_name = nodepool.get('name') if nodepool else ''
        return RuleViolation(
            resource_name=ke_cluster.name,
            resource_type=resource_mod.ResourceType.KE_CLUSTER,
            resource_id=ke_cluster.name,
            full_name=ke_cluster.full_name,
            rule_name=self.rule_name,
            rule_index=self.rule_index,
            violation_type='KE_VERSION_VIOLATION',
            violation_reason=violation_reason,
            project_id=ke_cluster.parent.id,
            cluster_name=ke_cluster.name,
            node_pool_name=node_pool_name,
            resource_data=ke_cluster.data)

    def _node_versions_valid(self, ke_cluster):
        """Check the node pool versions against the supported version list.

        Args:
            ke_cluster (KeCluster): KE Cluster and ServerConfig data.

        Returns:
            RuleViolation: A RuleViolation if the version is not supported,
                else None.
        """
        if not ke_cluster.server_config:
            LOGGER.warn('Server config missing from ke cluster, cannot check '
                        'if node versions are supported: %s', ke_cluster)
            return None
        supported_versions = ke_cluster.server_config.get('validNodeVersions')
        for nodepool in ke_cluster.node_pools:
            LOGGER.debug('Checking %s in cluster %s', nodepool.get('name'),
                         ke_cluster.name)
            if nodepool.get('version') not in supported_versions:
                violation = ('Node pool version %s is not supported (%s).' %
                             (nodepool.get('version'),
                              sorted(supported_versions)))

                return self._make_violation(ke_cluster, nodepool, violation)

    def _master_version_valid(self, ke_cluster):
        """Check the master version against the supported version list.

        Args:
            ke_cluster (KeCluster): KE Cluster and ServerConfig data.

        Returns:
            RuleViolation: A RuleViolation if the version is not supported,
                else None.
        """
        if not ke_cluster.server_config:
            LOGGER.warn('Server config missing from ke cluster, cannot check '
                        'if master version is supported: %s', ke_cluster)
            return None

        supported_versions = ke_cluster.server_config.get(
            'validMasterVersions')
        if ke_cluster.current_master_version not in supported_versions:
            violation = ('Master version %s is not supported (%s).' %
                         (ke_cluster.current_master_version,
                          sorted(supported_versions)))

            return self._make_violation(ke_cluster, None, violation)

    def _node_versions_allowed(self, ke_cluster):
        """Check the node pool versions against the allowed versions list.

        Args:
            ke_cluster (KeCluster): KE Cluster and ServerConfig data.

        Returns:
            RuleViolation: A RuleViolation if the version is not allowed,
                else None.
        """
        for nodepool in ke_cluster.node_pools:
            LOGGER.debug('Checking %s in cluster %s', nodepool.get('name'),
                         ke_cluster.name)
            version_allowed = any(
                version_rule.is_version_allowed(nodepool.get('version', ''))
                for version_rule in self.allowed_versions)
            if not version_allowed:
                violation = ('Node pool version %s is not allowed (%s).' %
                             (nodepool.get('version'),
                              sorted(repr(v) for v in self.allowed_versions)))

                return self._make_violation(ke_cluster, nodepool, violation)

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
                (self.check_valid_node_versions ==
                 other.check_valid_node_versions) and
                (self.check_valid_master_version ==
                 other.check_valid_master_version) and
                (self.allowed_versions ==
                 other.allowed_versions))

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
# violation_type: KE_VERSION_VIOLATION
# violation_reason: string
# project_id: string
# cluster_name: string
# node_pool_name: string
RuleViolation = namedtuple('RuleViolation',
                           ['resource_type', 'resource_id', 'full_name',
                            'rule_name', 'rule_index', 'violation_type',
                            'violation_reason', 'project_id',
                            'cluster_name', 'node_pool_name',
                            'resource_data', 'resource_name'])
