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
"""Rules engine for checking crypto keys configuration."""

from collections import namedtuple
import json
import threading

from google.cloud.forseti.common.gcp_type import errors as resource_errors
from google.cloud.forseti.common.gcp_type import resource as resource_mod
from google.cloud.forseti.common.gcp_type import resource_util
from google.cloud.forseti.common.util import logger, date_time, string_formats
from google.cloud.forseti.scanner.audit import base_rules_engine as bre
from google.cloud.forseti.scanner.audit import errors as audit_errors

LOGGER = logger.get_logger(__name__)


class KMSRulesEngine(bre.BaseRulesEngine):
    """Rules engine for KMS scanner."""

    def __init__(self, rules_file_path, snapshot_timestamp=None):
        """Initialize.

        Args:
            rules_file_path (str): file location of rules
            snapshot_timestamp (str): snapshot timestamp. Defaults to None.
                If set, this will be the snapshot timestamp
                used in the engine.
        """
        super(KMSRulesEngine,
              self).__init__(rules_file_path=rules_file_path)
        self.rule_book = None
        self.snapshot_timestamp = snapshot_timestamp
        self._lock = threading.Lock()

    def build_rule_book(self, global_configs=None):
        """Build KMSRuleBook from the rules definition file.

        Args:
            global_configs (dict): Global configurations.
        """
        with self._lock:
            self.rule_book = KMSRuleBook(
                self._load_rule_definitions())

    def find_violations(self, keys, force_rebuild=False):
        """Determine whether crypto key configuration violates rules.

        Args:
            keys (CryptoKeys): A crypto key resource to check.
            force_rebuild (bool): If True, rebuilds the rule book. This will
                reload the rules definition file and add the rules to the book.

        Returns:
             generator: A generator of rule violations.
        """
        if self.rule_book is None or force_rebuild:
            self.build_rule_book()

        violations = self.rule_book.find_violations(keys)

        return set(violations)

    def add_rules(self, rules):
        """Add rules to the rule book.

        Args:
            rules (list): The list of rules to add to the book.
        """
        if self.rule_book is not None:
            self.rule_book.add_rules(rules)


class KMSRuleBook(bre.BaseRuleBook):
    """The RuleBook for crypto key rules."""

    def __init__(self, rule_defs=None):
        """Initialization.

        Args:
            rule_defs (list): CryptoKeys rule definition dicts
        """
        super(KMSRuleBook, self).__init__()
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
                try:
                    resource_type = resource_mod.ResourceType.verify(
                        resource.get('type'))
                except resource_errors.InvalidResourceTypeError:
                    raise audit_errors.InvalidRulesSchemaError(
                        'Missing resource type in rule {}'.format(rule_index))

                if not resource_ids or len(resource_ids) < 1:
                    raise audit_errors.InvalidRulesSchemaError(
                        'Missing resource ids in rule {}'.format(rule_index))
                key_rotation_period = rule_def.get('key').get('rotation_period')

                # For each resource id associated with the rule, create a
                # mapping of resource => rules.
                for resource_id in resource_ids:
                    gcp_resource = resource_util.create_resource(
                        resource_id=resource_id,
                        resource_type=resource_type)

                    rule = Rule(
                        rule_def.get('name'),
                        rule_index,
                        key_rotation_period)

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

    def find_violations(self, keys):
        """Find violations in the rule book.

        Args:
            keys (CryptoKeys): crypto key resource.

        Returns:
            list: RuleViolation
        """
        LOGGER.debug('Looking for crypto key violations: %s',
                     keys.full_name)
        violations = []
        resource_ancestors = resource_util.get_ancestors_from_full_name(
            keys.full_name)

        LOGGER.debug('Ancestors of resource: %r', resource_ancestors)

        checked_wildcards = set()
        for curr_resource in resource_ancestors:
            if not curr_resource:
                # The leaf node in the hierarchy
                continue

            resource_rule = self.get_resource_rules(curr_resource)
            if resource_rule:
                violations.extend(
                    resource_rule.find_violations(keys))

            wildcard_resource = resource_util.create_resource(
                resource_id='*', resource_type=curr_resource.type)
            if wildcard_resource in checked_wildcards:
                continue
            checked_wildcards.add(wildcard_resource)
            resource_rule = self.get_resource_rules(wildcard_resource)
            if resource_rule:
                violations.extend(
                    resource_rule.find_violations(keys))

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

    def find_violations(self, keys):
        """Determine if the policy binding matches this rule's criteria.

        Args:
            keys (CryptoKeys): crypto keys resource.

        Returns:
            list: RuleViolation
        """
        violations = []
        for rule in self.rules:
            rule_violations = rule.find_violations(keys)
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
        return 'KMSResourceRules<resource={}, rules={}>'.format(
            self.resource, self.rules)


class Rule(object):
    """Rule properties from the rule definition file, also finds violations."""

    def __init__(self, rule_name, rule_index,
                 key_rotation_period):
        """Initialize.

        Args:
            rule_name (str): Name of the loaded rule
            rule_index (int): The index of the rule from the rule definitions
            key_rotation_period (string): Rotation Period of the CryptoKey
        """
        self.rule_name = rule_name
        self.rule_index = rule_index
        self.key_rotation_period = key_rotation_period

    def is_more_than_max_rotation_period(self,
                                         gcp_rotation_period):
        """Check if the rotation period has been disabled. key has been rotated: is the key creation time older
        than max_age in the policy

        Args:
            created_time (str): The time at which the key was created (this
                is the validAfterTime in the key API response (in
                string_formats.DEFAULT_FORSETI_TIMESTAMP) format
            scan_time (datetime): Snapshot timestamp.

        Returns:
            bool: Returns true if un_rotated
        """

        if gcp_rotation_period > self.key_rotation_period:
            return True
        return False

    def find_violations(self, crypto_keys):
        """Find service account key age violations based on the max_age.

        Args:
            service_account (ServiceAccount): ServiceAccount object.

        Returns:
            list: Returns a list of RuleViolation named tuples
        """

        violations = []
        for key in crypto_keys:
            key_id = key.get('key_id')
            full_name = key.get('full_name')
            LOGGER.debug('Checking key rotation for %s', full_name)
            key_rotation_period = key.get('rotation_period')
            if self.is_more_than_max_rotation_period(key_rotation_period, ):
                violation_reason = ('Key ID %s rotation period is greated than'
                                    ' %s days.' % (key_id, key_rotation_period))

            return violations

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
                (self.key_rotation_period == other.key_rotation_period))

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
# RuleViolation = namedtuple('RuleViolation',
#                            ['resource_type', 'resource_id', 'resource_name',
#                             'service_account_name', 'full_name', 'rule_name',
#                             'rule_index', 'violation_type', 'violation_reason',
#                             'project_id', 'key_id', 'key_created_time',
#                             'resource_data'])
