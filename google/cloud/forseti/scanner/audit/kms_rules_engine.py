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
import itertools
import json
import re
import threading

from google.cloud.forseti.common.gcp_type import errors as resource_errors
from google.cloud.forseti.common.gcp_type import resource as resource_mod
from google.cloud.forseti.common.gcp_type import resource_util
from google.cloud.forseti.common.util import logger, date_time, string_formats
from google.cloud.forseti.scanner.audit import base_rules_engine as bre
from google.cloud.forseti.scanner.audit import errors as audit_errors

LOGGER = logger.get_logger(__name__)

SUPPORTED_RULE_RESOURCE_TYPES = frozenset(['project', 'folder', 'organization'])

VIOLATION_TYPE = 'LOG_SINK_VIOLATION'

# Rule Modes.
WHITELIST = 'whitelist'
BLACKLIST = 'blacklist'
REQUIRED = 'required'
RULE_MODES = frozenset([WHITELIST, BLACKLIST, REQUIRED])


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

    def find_violations(self, key,  force_rebuild=False):
        """Determine whether crypto key configuration violates rules.

        Args:
            resource (gcp_type): The resource that the log sinks belong to.
            keys (CryptoKeys): A crypto key resource to check.
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

    # def parse_key_config(key):
    #     """Validates and escapes a crypto key from a rule config.
    #
    #     Args:
    #         key (dict): A sink definition from a LogSink rule definition.
    #
    #     Returns:
    #         dict: A sink definition with fields escaped and globified, or None if
    #         sink_spec is invalid.
    #     """
    #
    #     if not key:
    #         return None
    #
    #     key_rotation_period = key.get('rotation_period')
    #     All fields are mandatory
        # if any(item is None for item in [key_rotation_period]):
        #     return None


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
        return 'LogSinkRuleBook <{}>'.format(self.resource_rules_map)

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
        rule_def = rule_def
        LOGGER.info(rule_def)
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

            try:
                for k in key:
                    key_rotation_period = k.get('rotation_period')
            except (ValueError, TypeError):
                raise audit_errors.InvalidRulesSchemaError(
                    'Rotation period of crypto key is either missing or '
                    ' not an integer in rule {}'.format(rule_index))

            # For each resource id associated with the rule, create a
            # mapping of resource => rules.
            for resource_id in resource_ids:
                gcp_resource = resource_util.create_resource(
                    resource_id=resource_id,
                    resource_type=resource_type)

                rule_def_resource = {
                    'key': key,
                    'mode': mode,
                }
                rule = Rule(rule_name=rule_def.get('name'),
                            rule_index=rule_index,
                            rule=rule_def_resource)

                resource_rules = self.resource_rules_map.get(rule_index)

                resource_rules = self.resource_rules_map.setdefault(
                    gcp_resource, ResourceRules(resource=gcp_resource))

                if not resource_rules:
                    self.resource_rules_map[rule_index] = rule
                if resource_rules:
                    LOGGER.info('SUCCESS')
                if rule not in resource_rules.rules:
                    resource_rules.rules.add(rule)
                if resource_rules:
                    LOGGER.info('SUCCESS')

    # pylint: enable=invalid-name

    def get_resource_rules(self, resource):
        """Get all the resource rules for resource.

        Args:
            resource (Resource): The gcp_type Resource find in the map.

        Returns:
            ResourceRules: A ResourceRules object.
        """
        results = self.resource_rules_map.get(resource)
        return results

    def find_violations(self, key):
        """Find crypto key violations in the rule book.

        Args:
            key (CryptoKey): The GCP resource to check locations for.

        Returns:
            RuleViolation: resource crypto key rule violations.
        """

        violations = itertools.chain()

        # Check for rules that apply to this resource directly.
        # resource_rules = self.resource_rules_map['self']
        # for rule in resource_rules:
        #     LOGGER.info('rule:', rule)
        #     violations = itertools.chain(
        #         violations, rule.find_violations(key))

        LOGGER.debug('Looking for crypto key violations: %s',
                     key.name)
        violations = []
        resource_ancestors = resource_util.get_ancestors_from_full_name(
            key.name)

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
        v = violations
        return v

    # def key_matches_rule(rule_def, key):
    #     """Returns true if the crypto key matches the rule's key definition.
    #
    #     Args:
    #         rule_def (dict): key rule definition.
    #         key (CryptoKey): key being matched to the rule definition.
    #
    #     Returns:
    #         bool: True if key matches rule definition.
    #     """
        # protection_level = key.primary_version.get('protectionLevel')
        # algorithm = key.primary_version.get('algorithm')
        # state = key.primary_version.get('state')
        # purpose = key.purpose
        #
        # if (not re.match(rule_def['protection_level'], protection_level) or
        #         not re.match(rule_def['algorithm'], algorithm) or
        #         not re.match(rule_def['state'], state) or
        #         not re.match(rule_def['purpose'], purpose)):
        #     return False
        # return True

    # def find_whitelist_violations(rule_def, keys):
    #     violating_keys = []
    #     for key in keys:
    #         if not KMSRuleBook.key_matches_rule(rule_def, key):
    #             violating_keys.append(key)
    #     return violating_keys
    #
    # def find_blacklist_violations(rule_def, keys):
    #     violating_keys = []
    #     for key in keys:
    #         if not KMSRuleBook.key_matches_rule(rule_def, key):
    #             keys.append(key)
    #     return violating_keys


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

    def is_more_than_max_rotation_period(self, last_rotation_time, scan_time):
        """Check if the key has been rotated within the time speciifed in the
         policy.

        Args:
            last_rotation_time (str): The time at which the key was last
             rotated.
            scan_time (datetime): Snapshot timestamp.

        Returns:
            bool: Returns true if key was not rotated within the time specified
            in the policy.
        """

        scan_time = date_time.get_utc_now_datetime()
        last_rotation_time = last_rotation_time

        # last_rotation_time = date_time.get_datetime_from_string(
        #     last_rotation_time, string_formats.DEFAULT_FORSETI_TIMESTAMP)

        print('Scan time:', scan_time)
        print('last rotation time:', last_rotation_time)

        # last_rotation_time = date_time.get_datetime_from_string(
        #     last_rotation_time, string_formats.DEFAULT_FORSETI_TIMESTAMP)
        # scan_time = datetime.datetime.now()
        # print('Scan time:', scan_time)
        # print('last rotation time:', last_rotation_time)
        # diff = scan_time-last_rotation_time

        # if (scan_time - last_rotation_time).days <= (
        #         self.rule.get('key').get('rotation_period')):
        #     return False
        # return True

    def find_violations(self, key):
        """Find crypto key violations based on the max_age.

        Args:
            key (Resource): The resource to check for violations.

        Returns:
            list: Returns a list of RuleViolation named tuples
        """

        scan_time = date_time.get_utc_now_datetime()

        violations = []

        name = key.name
        next_rotation_time = key.next_rotation_time
        last_rotation_time = key.primary_version.get('createTime')
        # last_rotation_time = datetime.datetime.strptime(last_rotation_time, "%Y-%m-%d")
        if self.rule['mode'] == BLACKLIST:
            # res = self.is_more_than_max_rotation_period(
            #         last_rotation_time, scan_time)
            res = True
            if res:
                violation_reason = ('Key %s not rotated since %s.' %
                                    (name, last_rotation_time))
        violations.append(RuleViolation(
            resource_id=key.id,
            resource_type=key.type,
            resource_name=key.name,
            full_name=key.crypto_key_type,
            rule_index=self.rule_index,
            rule_name=self.rule_name,
            violation_type='CRYPTO_KEY_VIOLATION',
            primary_version=key.primary_version,
            next_rotation_time=key.next_rotation_time,
            rotation_period=key.rotation_period,
            last_rotation_time=last_rotation_time,
            violation_reason=violation_reason,
            key_creation_time=key.create_time,
            version_creation_time=key.primary_version.get('createTime'),
            resource_data=key.data))

        v = violations
        return v

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
# resource_name: string
# primary_version: string
# next_rotation_time: string
# rule_name: string
# rule_index: int
# violation_type: CRYPTO_KEY_VIOLATION
# violation_reason: string
# rotation_period: string
# last_rotation_time: string
# key_creation_time: string
# resource_data: string
RuleViolation = namedtuple('RuleViolation',
                           ['resource_id', 'resource_type', 'resource_name',
                            'full_name', 'rule_index', 'rule_name',
                            'violation_type', 'violation_reason',
                            'primary_version', 'next_rotation_time',
                            'rotation_period', 'last_rotation_time',
                            'key_creation_time', 'version_creation_time',
                            'resource_data'])

