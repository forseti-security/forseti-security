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
from collections import namedtuple
import itertools
import threading

from google.cloud.forseti.common.gcp_type import resource_util
from google.cloud.forseti.common.util import logger
from google.cloud.forseti.common.util import relationship
from google.cloud.forseti.scanner.audit import base_rules_engine as bre
from google.cloud.forseti.scanner.audit import errors as audit_errors


LOGGER = logger.get_logger(__name__)

SUPPORTED_RETENTION_RESOURCE_TYPES = frozenset(['bucket'])

VIOLATION_TYPE = 'RETENTION_VIOLATION'
_APPLY_TO_BUCKETS = 'bucket'
_APPLY_TO_RESOURCES = frozenset([_APPLY_TO_BUCKETS])


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

    def find_violations(self, buckets_lifecycle, force_rebuild=False):
        """Determine whether bucket lifecycle violates rules.

        Args:
            buckets_lifecycle (retention_bucket.RetentionBucket): Object
                containing lifecycle data
            force_rebuild (bool): If True, rebuilds the rule book. This will
                reload the rules definition file and add the rules to the book.

        Returns:
             generator: A generator of rule violations.
        """
        if self.rule_book is None or force_rebuild:
            self.build_rule_book()

        violations = itertools.chain()

        resource_rules = self.rule_book.get_resource_rules(_APPLY_TO_BUCKETS)

        resource_ancestors = (relationship.find_ancestors(
            buckets_lifecycle, buckets_lifecycle.full_name))
        for related_resources in resource_ancestors:
            rules = resource_rules[related_resources]
            for rule in rules:
                violations = itertools.chain(
                    violations,
                    rule.find_violations(buckets_lifecycle))

        return set(violations)


def get_retention_range(rule_def, rule_index):
    """Get the min and max value of the retention.

    Args:
        rule_def (dict): A dictionary containing rule definition
            properties.
        rule_index (int): The index of the rule from the rule definitions.
            Assigned automatically when the rule book is built.

    Returns:
        pair: the minimum and maximum value of the Age.
    """
    minimum_retention = rule_def.get('minimum_retention', None)
    maximum_retention = rule_def.get('maximum_retention', None)
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
            for applies_to in _APPLY_TO_RESOURCES}
        if not rule_defs:
            self.rule_defs = {}
        else:
            self.rule_defs = rule_defs
            self.add_rules(rule_defs)

    def add_rules(self, rule_defs):
        """Add rules to the rule book

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
        self._rules_sema.acquire()
        try:
            applies_to = rule_def.get('applies_to')
            if applies_to is None:
                raise audit_errors.InvalidRulesSchemaError(
                    'Lack of applies_to in rule {}'.format(rule_index))

            retention_range = get_retention_range(rule_def, rule_index)

            if any(x not in _APPLY_TO_RESOURCES for x in applies_to):
                raise audit_errors.InvalidRulesSchemaError(
                    'Invalid applies_to resource in rule {}'.format(rule_index))

            for appto in applies_to:
                self.create_and_add_rule(
                    rule_def,
                    rule_index,
                    appto,
                    retention_range[0],
                    retention_range[1])
                # other appto add here
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
        resource = rule_def.get('resource', None)
        if resource is None:
            raise audit_errors.InvalidRulesSchemaError(
                'Lack of resource in rule {}'.format(rule_index))

        for res in resource:
            resource_type = res.get('type', None)
            if resource_type is None:
                raise audit_errors.InvalidRulesSchemaError(
                    'Lack of type in rule {}'.format(rule_index))

            resource_ids = res.get('resource_ids', None)
            if resource_ids is None:
                raise audit_errors.InvalidRulesSchemaError(
                    'Lack of resource_ids in rule {}'.format(rule_index))

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
        """Get all the resource rules for (resource, RuleAppliesTo.*).
        Args:
            applies_to (str): The name of applies_to resource

        Returns:
           defaultdict:  A list of ResourceRules.
        """
        return self.resource_rules_map[applies_to]


class Rule(object):
    """Rule properties from the rule definition file.
    Also finds violations.
    """

    RuleViolation = namedtuple(
        'RuleViolation',
        ['resource_name', 'resource_type', 'full_name', 'rule_name',
         'rule_index', 'violation_type', 'violation_describe'])

    def __init__(self, rule_name, rule_index, min_retention, max_retention):
        """Initialize.

        Args:
            rule_name (str): Name of the loaded rule
            rule_index (int): The index of the rule
            min_retention(int): minimum value of the age in lifecycle
            max_retention(int): maximum value of the age in lifecycle
        """
        self.rule_name = rule_name
        self.rule_index = rule_index
        self.min_retention = min_retention
        self.max_retention = max_retention

    def generate_rule_violation(self, buckets_lifecycle, describe):
        """generate a violation.

        Args:
            buckets_lifecycle (RetentionBucket): The info of the bucket
            describe (str): The description of the violation
        Returns:
            RuleViolation: The violation
        """
        return self.RuleViolation(
            resource_name=buckets_lifecycle.id,
            resource_type=buckets_lifecycle.type,
            full_name=buckets_lifecycle.full_name,
            rule_name=self.rule_name,
            rule_index=self.rule_index,
            violation_type=VIOLATION_TYPE,
            violation_describe=describe
        )

    def find_violations(self, res):
        """Get a generator for violations
        Args:
            res (Resource): A class derived from Resource
        Yields:
            RuleViolation: All violations of the bucket breaking the rule.
        """

        minretention = self.min_retention
        maxretention = self.max_retention
        exist_match = False
        for retention_item in res.retentions:
            if not retention_item.exist_valid_action:
                continue

            age = retention_item.retention
            if age is None:
                continue
            if(minretention != None and age < minretention):
                yield self.generate_rule_violation(
                    res,
                    'age %d is smaller than '
                    'the minimum retention %d' % (age, minretention))
                continue
            if(maxretention != None and age > maxretention):
                yield self.generate_rule_violation(
                    res,
                    'age %d is larger than '
                    'the maximum retention %d' % (age, maxretention))
                continue
            if retention_item.exist_other_conditions:
                continue
            exist_match = True
        if exist_match is not True:
            yield self.generate_rule_violation(
                res,
                'No condition satisfies '
                'the rule (min %s, max %s)' % (str(minretention),
                                               str(maxretention)))
