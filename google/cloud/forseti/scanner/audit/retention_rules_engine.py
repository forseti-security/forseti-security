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

"""Rules engine for Bucket retention."""
import collections
import itertools
import threading
import json

from google.cloud.forseti.common.gcp_type import resource_util
from google.cloud.forseti.common.util import date_time as dt
from google.cloud.forseti.common.util import logger
from google.cloud.forseti.common.util import relationship
from google.cloud.forseti.scanner.audit import base_rules_engine as bre
from google.cloud.forseti.scanner.audit import errors as audit_errors


LOGGER = logger.get_logger(__name__)

SUPPORTED_RETENTION_RES_TYPES = frozenset(['bucket'])
VIOLATION_TYPE = 'RETENTION_VIOLATION'

RuleViolation = collections.namedtuple(
    'RuleViolation',
    ['resource_name', 'resource_type', 'full_name', 'rule_name',
     'rule_index', 'violation_type', 'violation_data', 'resource_data',
     'resource_id'])


class RetentionRulesEngine(bre.BaseRulesEngine):
    """Rules engine for retention."""

    def __init__(self, rules_file_path, snapshot_timestamp=None):
        """Initialize.

        Args:
            rules_file_path (str): file location of rules
            snapshot_timestamp (str): snapshot timestamp. Defaults to None.
                If set, this will be the snapshot timestamp
                used in the engine.
        """
        super(RetentionRulesEngine,
              self).__init__(rules_file_path=rules_file_path)
        self.rule_book = None

    def build_rule_book(self, global_configs=None):
        """Build RetentionRuleBook from the rules definition file.

        Args:
            global_configs (dict): Global configurations.
        """
        self.rule_book = RetentionRuleBook(self._load_rule_definitions())

    def find_violations(self, resource, force_rebuild=False):
        """Determine whether bucket lifecycle violates rules.

        Args:
            resource (Resource): Object
                containing lifecycle data
            force_rebuild (bool): If True, rebuilds the rule book. This will
                reload the rules definition file and add the rules to the book.

        Returns:
             generator: A generator of rule violations.
        """
        if self.rule_book is None or force_rebuild:
            self.build_rule_book()

        violations = itertools.chain()
        resource_rules = self.rule_book.get_resource_rules(resource.type)
        resource_ancestors = (relationship.find_ancestors(
            resource, resource.full_name))

        for related_resources in resource_ancestors:
            rules = resource_rules.get(related_resources, [])
            for rule in rules:
                violations = itertools.chain(
                    violations,
                    rule.find_violations(resource))

        return set(violations)


def get_retention_range(rule_def, rule_index):
    """Get the min and max value of the retention.

    Args:
        rule_def (dict): A dictionary containing rule definition properties.
        rule_index (int): The index of the rule from the rule definitions.
            Assigned automatically when the rule book is built.

    Returns:
        pair: the minimum and maximum value of the Age.
    """
    minimum_retention = rule_def.get('minimum_retention')
    maximum_retention = rule_def.get('maximum_retention')
    if minimum_retention is None and maximum_retention is None:
        raise audit_errors.InvalidRulesSchemaError(
            'Lack of minimum_retention and '
            'maximum_retention in rule {}'.format(rule_index))
    elif minimum_retention != None and maximum_retention != None:
        if minimum_retention > maximum_retention:
            raise audit_errors.InvalidRulesSchemaError(
                'minimum_retention larger than '
                'maximum_retention in rule {}'.format(rule_index))
    return minimum_retention, maximum_retention


class RetentionRuleBook(bre.BaseRuleBook):
    """The RuleBook for Retention resources."""

    def __init__(self, rule_defs=None):
        """Initialization.

        Args:
            rule_defs (dict): rule definitons
        """
        super(RetentionRuleBook, self).__init__()
        self._rules_sema = threading.BoundedSemaphore(value=1)

        self.resource_rules_map = {
            applies_to: collections.defaultdict(set)
            for applies_to in SUPPORTED_RETENTION_RES_TYPES}
        if not rule_defs:
            self.rule_defs = {}
        else:
            self.rule_defs = rule_defs
            self.add_rules(rule_defs)

    def add_rules(self, rule_defs):
        """Add rules to the rule book.

        Args:
            rule_defs (dict): rule definitions dictionary.
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
        self._rules_sema.acquire()
        try:
            applies_to = rule_def.get('applies_to')
            if applies_to is None:
                raise audit_errors.InvalidRulesSchemaError(
                    'Lack of applies_to in rule {}'.format(rule_index))

            minimum_retention, maximum_retention = get_retention_range(
                rule_def, rule_index)

            if any(support_type not in SUPPORTED_RETENTION_RES_TYPES
                   for support_type in applies_to):
                raise audit_errors.InvalidRulesSchemaError(
                    'Invalid applies_to resource in rule {}'.format(rule_index))

            added_applies_to = set()

            for appto in applies_to:
                if appto in added_applies_to:
                    raise audit_errors.InvalidRulesSchemaError(
                        'redundant applies_to in rule {}'.format(rule_index))
                added_applies_to.add(appto)

                self.create_and_add_rule(
                    rule_def,
                    rule_index,
                    appto,
                    minimum_retention,
                    maximum_retention)
        finally:
            self._rules_sema.release()

    def create_and_add_rule(self, rule_def, rule_index, apply_to,
                            min_retention, max_retention):
        """Add a rule to the rule book.

        Args:
            rule_def (dict): A dictionary containing rule definition
                properties.
            rule_index (int): The index of the rule from the rule definitions.
                Assigned automatically when the rule book is built.
            apply_to (str): The resource type that the rule is applied to
            min_retention(int): minimum value of the age in lifecycle
            max_retention(int): maximum value of the age in lifecycle
        """
        if 'resource' not in rule_def:
            raise audit_errors.InvalidRulesSchemaError(
                'Lack of resource in rule {}'.format(rule_index))
        resources = rule_def['resource']

        for res in resources:
            if 'type' not in res:
                raise audit_errors.InvalidRulesSchemaError(
                    'Lack of type in rule {}'.format(rule_index))
            resource_type = res['type']

            if 'resource_ids' not in res:
                raise audit_errors.InvalidRulesSchemaError(
                    'Lack of resource_ids in rule {}'.format(rule_index))
            resource_ids = res['resource_ids']

            rule = Rule(rule_name=rule_def.get('name'),
                        rule_index=rule_index,
                        min_retention=min_retention,
                        max_retention=max_retention)

            for rid in resource_ids:
                if rid == '*':
                    raise audit_errors.InvalidRulesSchemaError(
                        'The symbol * is not allowed in rule {}'.format(
                            rule_index))

                gcp_resource = resource_util.create_resource(
                    resource_id=rid,
                    resource_type=resource_type)

                self.resource_rules_map[apply_to][gcp_resource].add(
                    rule)

    def get_resource_rules(self, applies_to):
        """Get all the rules for the resource "applies_to".

        Args:
            applies_to (str): The type of the resource

        Returns:
           defaultdict:  A list of ResourceRules.
        """
        return self.resource_rules_map[applies_to]


class Rule(object):
    """Rule properties from the rule definition file. Also finds violations."""

    def __init__(self, rule_name, rule_index, min_retention, max_retention):
        """Initialize.

        Args:
            rule_name (str): Name of the loaded rule.
            rule_index (int): The index of the rule.
            min_retention(int): minimum value of the age in lifecycle.
            max_retention(int): maximum value of the age in lifecycle.
        """
        self.rule_name = rule_name
        self.rule_index = rule_index
        self.min_retention = min_retention
        self.max_retention = max_retention

    def generate_bucket_violation(self, bucket):
        """Generate a violation.

        Args:
            bucket (Bucket): The bucket that triggers the violation.
        Returns:
            RuleViolation: The violation.
        """
        data_lifecycle = bucket.get_lifecycle_rule()
        data_lifecycle_str = json.dumps(data_lifecycle)

        return RuleViolation(
            resource_name=bucket.name,
            resource_id=bucket.id,
            resource_type=bucket.type,
            full_name=bucket.full_name,
            rule_name=self.rule_name,
            rule_index=self.rule_index,
            violation_type=VIOLATION_TYPE,
            violation_data=data_lifecycle_str,
            resource_data=bucket.data,
        )

    def find_violations(self, res):
        """Get a generator for violations.

        Args:
            res (Resource): A class derived from Resource.
        Returns:
            Generator: All violations of the resource breaking the rule.

        Raises:
            ValueError: Raised if the resource type is bucket.
        """

        if res.type == 'bucket':
            return self.find_violations_in_bucket(res)
        raise ValueError(
            'only bucket is currently supported'
        )

    def bucket_max_retention_violation(self, bucket):
        """Get a generator for violations especially for maximum retention
           It only supports bucket for now, and will work on generalizing
           in future PRs.

        Args:
            bucket (bucket): Find violation from the bucket.
        Yields:
            RuleViolation: All max violations of the bucket breaking the rule.
        """
        if self.max_retention is None:
            return

        # There should be a condition which guarantees to delete data
        bucket_lifecycle = bucket.get_lifecycle_rule()
        if bucket_lifecycle:
            for lc_item in bucket_lifecycle:
                if lc_item.get('action', {}).get('type') == 'Delete':
                    conditions = lc_item.get('condition', {})
                    age = conditions.get('age')
                    if age is not None and len(conditions) == 1:
                        # the config does not have conditions other than age
                        if age <= self.max_retention:
                            return
        yield self.generate_bucket_violation(bucket)

    def bucket_min_retention_violation(self, bucket):
        """Get a generator for violations especially for minimum retention.

        Args:
            bucket (bucket): Find violation from the bucket.
        Yields:
            RuleViolation: All min violations of the bucket breaking the rule.
        """
        if self.min_retention is None:
            return

        bucket_lifecycle = bucket.get_lifecycle_rule()
        for lc_item in bucket_lifecycle:
            if (lc_item.get('action', {}).get('type') == 'Delete' and
                    not bucket_conditions_guarantee_min(
                        lc_item.get('condition', {}), self.min_retention)):
                yield self.generate_bucket_violation(bucket)

    def find_violations_in_bucket(self, bucket):
        """Get a generator for violations.

        Args:
            bucket (bucket): Find violation from the buckets.
        Returns:
            Generator: All violations of the buckets breaking rules.
        """

        violation_max = self.bucket_max_retention_violation(bucket)
        violation_min = self.bucket_min_retention_violation(bucket)
        return itertools.chain(violation_max, violation_min)


def bucket_conditions_guarantee_min(conditions, min_retention):
    """Check if other conditions can guarantee minimum retention.

    Args:
        conditions (dict): the condition dict of the bucket
        min_retention (int): the value of minimum retention.
    Returns:
        bool: True: min is guaranteed even if age is too small.
    """
    age = conditions.get('age')
    if age is not None and age >= min_retention:
        return True
    # if createdBefore is old enough, it's OK.
    if 'createdBefore' in conditions:
        created_before = conditions['createdBefore']
        dt_cfg = dt.get_datetime_from_string(created_before,
                                             '%Y-%m-%d')
        dt_now = dt.get_utc_now_datetime()
        day_diff = (dt_now - dt_cfg).days
        if day_diff >= min_retention:
            return True

    # if number of new version is larger than 0, OK.
    if conditions.get('numNewerVersions', 0) >= 1:
        return True

    return False
