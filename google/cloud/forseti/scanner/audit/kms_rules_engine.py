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
import datetime
import threading

from google.cloud.forseti.common.gcp_type import resource_util
from google.cloud.forseti.common.util import logger, date_time, string_formats
from google.cloud.forseti.scanner.audit import base_rules_engine as bre
from google.cloud.forseti.scanner.audit import errors as audit_errors

LOGGER = logger.get_logger(__name__)

VIOLATION_TYPE = 'CRYPTO_KEY_VIOLATION'

# Rule Modes.
WHITELIST = 'whitelist'
BLACKLIST = 'blacklist'
RULE_MODES = frozenset([BLACKLIST, WHITELIST])


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

    def find_violations(self, key, force_rebuild=False):
        """Determine whether crypto key configuration violates rules.

        Args:
            key (CryptoKey): A crypto key resource to check.
            force_rebuild (bool): If True, rebuilds the rule book. This will
                reload the rules definition file and add the rules to the book.

        Returns:
             generator: A generator of rule violations.
        """
        res = self.rule_book is None or force_rebuild
        if res:
            self.build_rule_book()

        violations = self.rule_book.find_violations(key)

        return violations

    def add_rules(self, rules):
        """Add rules to the rule book.

        Args:
            rules (list): The list of rules to add to the book.
        """
        if self.rule_book is not None:
            self.rule_book.add_rules(rules)


class KMSRuleBook(bre.BaseRuleBook):
    """The RuleBook for crypto key rules."""

    supported_resource_types = frozenset([
        'organization'
    ])

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
        return 'KMSRuleBook <{}>'.format(self.resource_rules_map)

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
        resources = rule_def.get('resource')
        mode = rule_def.get('mode')
        key = rule_def.get('key')

        if not resources or key is None or mode not in RULE_MODES:
            raise audit_errors.InvalidRulesSchemaError(
                'Faulty rule {}'.format(rule_index))

        for resource in resources:
            resource_type = resource.get('type')
            resource_ids = resource.get('resource_ids')

            if resource_type not in self.supported_resource_types:
                raise audit_errors.InvalidRulesSchemaError(
                    'Invalid resource type in rule {}'.format(rule_index))

            if not resource_ids or len(resource_ids) < 1:
                raise audit_errors.InvalidRulesSchemaError(
                    'Missing resource ids in rule {}'.format(rule_index))

            # For each resource id associated with the rule, create a
            # mapping of resource => rules.
            for resource_id in resource_ids:
                gcp_resource = resource_util.create_resource(
                    resource_id=resource_id,
                    resource_type=resource_type)

                rule_def_resource = {
                    'key': key,
                    'mode': mode
                }
                rule = Rule(rule_name=rule_def.get('name'),
                            rule_index=rule_index,
                            rule=rule_def_resource)

                resource_rules = self.resource_rules_map.setdefault(
                    gcp_resource, ResourceRules(resource=gcp_resource))

                if not resource_rules:
                    self.resource_rules_map[rule_index] = rule
                if rule not in resource_rules.rules:
                    resource_rules.rules.add(rule)

    def get_resource_rules(self, resource):
        """Get all the resource rules for resource.

        Args:
            resource (Resource): The gcp_type Resource find in the map.

        Returns:
            ResourceRules: A ResourceRules object.
        """
        return self.resource_rules_map.get(resource)

    def find_violations(self, key):
        """Find crypto key violations in the rule book.

        Args:
            key (CryptoKey): The GCP resource to check for violations.

        Returns:
            RuleViolation: resource crypto key rule violations.
        """
        LOGGER.debug('Looking for crypto key violations: %s',
                     key.name)
        violations = []
        resource_ancestors = resource_util.get_ancestors_from_full_name(
            key.crypto_key_full_name)

        LOGGER.debug('Ancestors of resource: %r', resource_ancestors)

        checked_wildcards = set()
        for curr_resource in resource_ancestors:
            if not curr_resource:
                # The leaf node in the hierarchy
                continue

            resource_rule = self.get_resource_rules(curr_resource)
            if resource_rule:
                violations.extend(
                    resource_rule.find_violations(key))

            wildcard_resource = resource_util.create_resource(
                resource_id='*', resource_type=curr_resource.type)
            if wildcard_resource in checked_wildcards:
                continue
            checked_wildcards.add(wildcard_resource)
            resource_rule = self.get_resource_rules(wildcard_resource)
            if resource_rule:
                violations.extend(
                    resource_rule.find_violations(key))

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

    def find_violations(self, key):
        """Determine if the policy binding matches this rule's criteria.

        Args:
            key (CryptoKey): crypto key resource.

        Returns:
            list: RuleViolation
        """
        violations = []
        for rule in self.rules:
            rule_violations = rule.find_violations(key)
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

    def __init__(self, rule_name, rule_index, rule):
        """Initialize.

        Args:
            rule_name (str): Name of the loaded rule.
            rule_index (int): The index of the rule from the rule definitions.
            rule (dict): The rule definition from the file.
        """
        self.rule_name = rule_name
        self.rule_index = rule_index
        self.rule = rule

    @classmethod
    def find_match_rotation_period(cls, key, rotation_period, mode):
        """Check if there is a match for this rule rotation period against the
        given resource.

        If the mode is whitelist and days since the key was last rotated is less
        than or equals to the rotation period specified then there is no
        violation.

        If the mode is blacklist and days since the key was last rotated is
        greater than the rotation period specified then there is a violation.

        Args:
            key (Resource): The resource to check for a match.
            mode (string): The mode specified in the rule.
            rotation_period (string): The cut off rotation schedule of crypto
            key specified in rule file.

        Returns:
            bool: Returns true if a match is found.
        """
        LOGGER.debug('Formatting rotation time...')
        creation_time = key.primary_version.get('createTime')
        scan_time = date_time.get_utc_now_datetime()
        last_rotation_time = creation_time[:-5]
        formatted_last_rotation_time = datetime.datetime.strptime(
            last_rotation_time, string_formats.TIMESTAMP_MICROS)
        days_since_rotated = (scan_time - formatted_last_rotation_time).days
        if mode == BLACKLIST and days_since_rotated > rotation_period:
            return True
        elif mode == WHITELIST and days_since_rotated <= rotation_period:
            return True
        return False

    @classmethod
    def find_match_algorithms(cls, key, rule_algorithms):
        """Check if there is a match for this rule algorithm against the given
        resource.

        Args:
            key (Resource): The resource to check for a match.
            rule_algorithms (string): The algorithms of this rule.

        Returns:
            bool: Returns true if a match is found.
        """
        LOGGER.debug('Checking if the algorithm specified matches with that of'
                     ' crypto key.')
        key_algorithm = key.primary_version.get('algorithm')
        for algorithm in rule_algorithms:
            if key_algorithm == algorithm:
                return True
        return False

    @classmethod
    def find_match_protection_level(cls, key, rule_protection_level):
        """Check if there is a match for this rule protection level against the
         given resource.

        Args:
            key (Resource): The resource to check for a match.
            rule_protection_level (string): The protection level of this rule.

        Returns:
            bool: Returns true if a match is found.
        """
        key_protection_level = key.primary_version.get('protectionLevel')
        if key_protection_level == rule_protection_level:
            return True
        return False

    @classmethod
    def find_match_purpose(cls, key, rule_purpose):
        """Check if there is a match for this rule purpose against the given
        resource.

        Args:
            key (Resource): The resource to check for a match.
            rule_purpose (list): The purpose of this rule.

        Returns:
            bool: Returns true if a match is found.
        """
        key_purpose = key.purpose
        for purpose in rule_purpose:
            if key_purpose == purpose:
                return True
        return False

    @classmethod
    def find_match_state(cls, key, rule_state):
        """Check if there is a match for this rule state against the given
        resource.

        Args:
            key (Resource): The resource to check for a match.
            rule_state (list): The state of this rule.

        Returns:
            bool: Returns true if a match is found.
        """
        key_state = key.primary_version.get('state')
        for state in rule_state:
            if state == key_state:
                return True
        return False

    def find_violations(self, key):
        """Find violations for this rule against the given resource.

        Args:
            key (Resource): The resource to check for violations.

        Returns:
            list: Returns a list of RuleViolation named tuples.
        """
        violations = []
        state = key.primary_version.get('state')
        if not state == 'ENABLED':
            return violations

        mode = self.rule['mode']

        crypto_key_rule = self.rule['key']
        for key_data in crypto_key_rule:
            has_violation = False
            rule_algorithms = key_data.get('algorithms')
            rule_protection_level = key_data.get('protection_level')
            rule_purpose = key_data.get('purpose')
            rule_state = key_data.get('state')
            rotation_period = key_data.get('rotation_period')
            all_matched = True
            if rotation_period:
                all_matched = all_matched and self.find_match_rotation_period(
                    key, rotation_period, mode)
            if rule_algorithms:
                all_matched = all_matched and self.find_match_algorithms(
                    key, rule_algorithms)
            if rule_protection_level:
                all_matched = all_matched and self.find_match_protection_level(
                    key, rule_protection_level)
            if rule_purpose:
                all_matched = all_matched and self.find_match_purpose(
                    key, rule_purpose)
            if rule_state:
                all_matched = all_matched and self.find_match_state(
                    key, rule_state)

            if mode == BLACKLIST and all_matched:
                has_violation = True
            elif mode == WHITELIST and not all_matched:
                has_violation = True

            if has_violation:
                violations.append(RuleViolation(
                    resource_id=key.id,
                    resource_type=key.type,
                    resource_name=key.id,
                    full_name=key.crypto_key_full_name,
                    rule_index=self.rule_index,
                    rule_name=self.rule_name,
                    violation_type=VIOLATION_TYPE,
                    primary_version=key.primary_version,
                    next_rotation_time=key.next_rotation_time,
                    rotation_period=key.rotation_period,
                    state=key.primary_version.get('state'),
                    algorithm=key.primary_version.get('algorithm'),
                    protection_level=key.primary_version.get('protectionLevel'),
                    purpose=key.purpose,
                    key_creation_time=key.create_time,
                    resource_data=key.data))

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
                self.rule_index == other.rule_index)

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

        Returns:
            int: The hash of the rule index.
        """
        return hash(self.rule_index)


# pylint: enable=inconsistent-return-statements

# Rule violation.
# resource_type: string
# resource_id: string
# resource_name: string
# primary_version: string
# next_rotation_time: string
# rule_name: string
# rule_index: int
# full_name: string
# violation_type: CRYPTO_KEY_VIOLATION
# state: string
# purpose: string
# algorithm: string
# protection_level: string
# rotation_period: string
# key_creation_time: string
# resource_data: string
RuleViolation = namedtuple('RuleViolation',
                           ['resource_id', 'resource_type', 'resource_name',
                            'full_name', 'rule_index', 'rule_name',
                            'violation_type', 'state',
                            'primary_version', 'next_rotation_time',
                            'rotation_period', 'key_creation_time',
                            'algorithm', 'protection_level',
                            'purpose', 'resource_data'])
