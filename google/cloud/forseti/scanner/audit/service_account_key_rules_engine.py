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
"""Rules engine for checking service account key age."""

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


class ServiceAccountKeyRulesEngine(bre.BaseRulesEngine):
    """Rules engine for service account key scanner."""

    def __init__(self, rules_file_path, snapshot_timestamp=None):
        """Initialize.

        Args:
            rules_file_path (str): file location of rules
            snapshot_timestamp (str): snapshot timestamp. Defaults to None.
                If set, this will be the snapshot timestamp
                used in the engine.
        """
        super(ServiceAccountKeyRulesEngine,
              self).__init__(rules_file_path=rules_file_path)
        self.rule_book = None
        self.snapshot_timestamp = snapshot_timestamp
        self._lock = threading.Lock()

    def build_rule_book(self, global_configs=None):
        """Build ServiceAccountKeyRuleBook from the rules definition file.

        Args:
            global_configs (dict): Global configurations.
        """
        with self._lock:
            self.rule_book = ServiceAccountKeyRuleBook(
                self._load_rule_definitions())

    def find_violations(self, service_account, force_rebuild=False):
        """Determine whether service account key age violates rules.

        Args:
            service_account (ServiceAccount): A service account resource to
            check.
            force_rebuild (bool): If True, rebuilds the rule book. This will
                reload the rules definition file and add the rules to the book.

        Returns:
             generator: A generator of rule violations.
        """
        if self.rule_book is None or force_rebuild:
            self.build_rule_book()
        return self.rule_book.find_violations(service_account)


class ServiceAccountKeyRuleBook(bre.BaseRuleBook):
    """The RuleBook for service account key age rules."""

    def __init__(self, rule_defs=None):
        """Initialization.

        Args:
            rule_defs (list): Serviceaccount keys rule definition dicts
        """
        super(ServiceAccountKeyRuleBook, self).__init__()
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
                key_max_age_str = rule_def.get('max_age', None)

                try:
                    key_max_age = int(key_max_age_str)
                except (ValueError, TypeError):
                    raise audit_errors.InvalidRulesSchemaError(
                        'Service account key "max_age" missing or not an '
                        'integer in rule {}'.format(rule_index))

                # For each resource id associated with the rule, create a
                # mapping of resource => rules.
                for resource_id in resource_ids:
                    gcp_resource = resource_util.create_resource(
                        resource_id=resource_id,
                        resource_type=resource_type)

                    rule = Rule(
                        rule_def.get('name'),
                        rule_index,
                        key_max_age)

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

    def find_violations(self, service_account):
        """Find violations in the rule book.

        Args:
            service_account (ServiceAccount): service account resource.

        Returns:
            list: RuleViolation
        """
        LOGGER.debug('Looking for service account key violations: %s',
                     service_account.full_name)
        violations = []
        resource_ancestors = resource_util.get_ancestors_from_full_name(
            service_account.full_name)

        LOGGER.debug('Ancestors of resource: %r', resource_ancestors)

        checked_wildcards = set()
        for curr_resource in resource_ancestors:
            if not curr_resource:
                # The leaf node in the hierarchy
                continue

            resource_rule = self.get_resource_rules(curr_resource)
            if resource_rule:
                violations.extend(
                    resource_rule.find_violations(service_account))

            wildcard_resource = resource_util.create_resource(
                resource_id='*', resource_type=curr_resource.type)
            if wildcard_resource in checked_wildcards:
                continue
            checked_wildcards.add(wildcard_resource)
            resource_rule = self.get_resource_rules(wildcard_resource)
            if resource_rule:
                violations.extend(
                    resource_rule.find_violations(service_account))

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

    def find_violations(self, service_account):
        """Determine if the policy binding matches this rule's criteria.

        Args:
            service_account (ServiceAccount): service account resource.

        Returns:
            list: RuleViolation
        """
        violations = []
        for rule in self.rules:
            rule_violations = rule.find_violations(service_account)
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
        return 'ServiceAccountKeyResourceRules<resource={}, rules={}>'.format(
            self.resource, self.rules)


class Rule(object):
    """Rule properties from the rule definition file, also finds violations."""

    def __init__(self, rule_name, rule_index,
                 key_max_age):
        """Initialize.

        Args:
            rule_name (str): Name of the loaded rule
            rule_index (int): The index of the rule from the rule definitions
            key_max_age (int): Max allowed age in days of service
                account key
        """
        self.rule_name = rule_name
        self.rule_index = rule_index
        self.key_max_age = key_max_age

    def _is_more_than_max_age(self, created_time, scan_time):
        """Check if the key has been rotated: is the key creation time older
        than max_age in the policy

        Args:
            created_time (str): The time at which the key was created (this
                is the validAfterTime in the key API response (in
                string_formats.DEFAULT_FORSETI_TIMESTAMP) format
            scan_time (datetime): Snapshot timestamp.

        Returns:
            bool: Returns true if un_rotated
        """
        created_time = date_time.get_datetime_from_string(
            created_time, string_formats.DEFAULT_FORSETI_TIMESTAMP)

        if (scan_time - created_time).days > self.key_max_age:
            return True
        return False

    def find_violations(self, service_account):
        """Find service account key age violations based on the max_age.

        Args:
            service_account (ServiceAccount): ServiceAccount object.

        Returns:
            list: Returns a list of RuleViolation named tuples
        """

        # Note: We're checking the age as of "now", the scanner run time
        # We could consider changing this to when the key was inventoried.
        scan_time = date_time.get_utc_now_datetime()

        violations = []
        for key in service_account.keys:
            key_id = key.get('key_id')
            full_name = key.get('full_name')
            LOGGER.debug('Checking key rotation for %s', full_name)
            created_time = key.get('valid_after_time')
            if self._is_more_than_max_age(created_time, scan_time):
                violation_reason = ('Key ID %s not rotated since %s.' %
                                    (key_id, created_time))
                violations.append(RuleViolation(
                    resource_type=resource_mod.ResourceType.SERVICE_ACCOUNT_KEY,
                    resource_id=service_account.email,
                    resource_name=service_account.email,
                    service_account_name=service_account.display_name,
                    full_name=full_name,
                    rule_name='%s (older than %s days)' % (self.rule_name,
                                                           self.key_max_age),
                    rule_index=self.rule_index,
                    violation_type='SERVICE_ACCOUNT_KEY_VIOLATION',
                    violation_reason=violation_reason,
                    project_id=service_account.project_id,
                    key_id=key_id,
                    key_created_time=created_time,
                    resource_data=json.dumps(key, sort_keys=True)))

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
                (self.key_max_age == other.key_max_age))

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


RuleViolation = namedtuple('RuleViolation',
                           ['resource_type', 'resource_id', 'resource_name',
                            'service_account_name', 'full_name', 'rule_name',
                            'rule_index', 'violation_type', 'violation_reason',
                            'project_id', 'key_id', 'key_created_time',
                            'resource_data'])
