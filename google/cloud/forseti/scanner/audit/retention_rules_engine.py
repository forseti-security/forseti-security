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

"""Rules engine for Bucket acls."""
import collections
from collections import namedtuple
import itertools
import json
import re
import threading


from google.cloud.forseti.common.gcp_type import resource as resource_mod
from google.cloud.forseti.common.gcp_type import resource_util
from google.cloud.forseti.services import utils

from google.cloud.forseti.common.util import logger
from google.cloud.forseti.common.util.regular_exp import escape_and_globify
from google.cloud.forseti.scanner.audit import base_rules_engine as bre
from google.cloud.forseti.scanner.audit import errors as audit_errors


LOGGER = logger.get_logger(__name__)

VIOLATION_TYPE = 'RETENTION_VIOLATION'
# Applyto.
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

    def find_buckets_violations(self, buckets_lifecycle, force_rebuild=False):
        """Determine whether bucket lifecycle violates rules.

        Args:
            buckets_lifecycle (retention_bucket.RetentionBucket): Object containing lifecycle
                data
            force_rebuild (bool): If True, rebuilds the rule book. This will
                reload the rules definition file and add the rules to the book.

        Returns:
             generator: A generator of rule violations.
        """
        if self.rule_book is None or force_rebuild:
            self.build_rule_book()
        resource_rules = self.rule_book.get_resource_rules(_APPLY_TO_BUCKETS)

        violations = itertools.chain()
        for rule in resource_rules:
            violations = itertools.chain(
                violations,
                rule.find_buckets_violations(buckets_lifecycle))
        return set(violations)


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
            applies_to: []
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
            applies_to = rule_def.get("applies_to", None)
            if applies_to == None:
                raise audit_errors.InvalidRulesSchemaError(
                    'Lack of applies_to in rule {}'.format(rule_index))
            if type(applies_to).__name__ != "list":
                raise audit_errors.InvalidRulesSchemaError(
                    'Miss dash (-) near applies_to in rule {}'.format(rule_index))
            
            minimum_retention = rule_def.get("minimum_retention", None)
            maximum_retention = rule_def.get("maximum_retention", None)
            if minimum_retention == None and maximum_retention == None:
                raise audit_errors.InvalidRulesSchemaError(
                    'Lack of minimum_retention and maximum_retention in rule {}'.format(rule_index))
            elif minimum_retention != None and maximum_retention != None:
                if minimum_retention > maximum_retention:
                    raise audit_errors.InvalidRulesSchemaError(
                        'minimum_retention larger than maximum_retention in rule {}'.format(rule_index))
            
            applies_to_history = {}
            for appto in applies_to:
                if applies_to_history.has_key(appto):
                    raise audit_errors.InvalidRulesSchemaError(
                        'Duplicate applies_to in rule {}'.format(rule_index))
                applies_to_history[appto] = True
                
                if appto == "bucket":
                    self.add_bucket_rule(rule_def, rule_index, minimum_retention, maximum_retention)
                # other appto add here
        finally:
            self._rules_sema.release()

    def add_bucket_rule(self, rule_def, rule_index, min_retention, max_retention):
        """Add a rule to the rule book.

        Args:
            rule_def (dict): A dictionary containing rule definition
                properties.
            rule_index (int): The index of the rule from the rule definitions.
                Assigned automatically when the rule book is built.
        """
        resource = rule_def.get("resource", None)
        if resource == None:
            raise audit_errors.InvalidRulesSchemaError(
                'Lack of resource in rule {}'.format(rule_index))
        if type(resource).__name__ != "list":
            raise audit_errors.InvalidRulesSchemaError(
                'Miss dash (-) near resource in rule {}'.format(rule_index))

        for r in resource:
            resource_type = r.get("type", None)
            if resource_type == None:
                raise audit_errors.InvalidRulesSchemaError(
                    'Lack of type in rule {}'.format(rule_index))

            resource_ids = r.get("resource_ids", None)
            if resource_ids == None:
                raise audit_errors.InvalidRulesSchemaError(
                    'Lack of resource_ids in rule {}'.format(rule_index))
            if type(resource_ids).__name__ != "list":
                raise audit_errors.InvalidRulesSchemaError(
                    'Miss dash (-) near resource_ids in rule {}'.format(rule_index))
            for rid in resource_ids:
                if rid == "*":
                    raise audit_errors.InvalidRulesSchemaError(
                        'The symbol * is not allowed in rule {}'.format(rule_index))
        
        rule = Rule(rule_name=rule_def.get('name','no name'),
                            rule_index=rule_index,
                            applyto=_APPLY_TO_BUCKETS,
                            min_retention=min_retention,
                            max_retention=max_retention,
                            resource_type=resource_type,
                            resource_ids=resource_ids
                            )

        self.resource_rules_map[_APPLY_TO_BUCKETS].append(rule)

        

    def get_resource_rules(self, applies_to):
        """Get all the resource rules for (resource, RuleAppliesTo.*).

        Returns:
           list:  A list of ResourceRules.
        """
        return self.resource_rules_map[applies_to]


class Rule(object):
    """Rule properties from the rule definition file.
    Also finds violations.
    """

    rttRuleViolation = namedtuple(
        'RuleViolation',
        ['resource_name', 'resource_type', 'full_name', 'rule_name', 'rule_index',
         'violation_type', 'violation_describe'])

    def __init__(self, rule_name, rule_index, applyto, min_retention, max_retention, resource_type, resource_ids):
        """Initialize.

        Args:
            rule_name (str): Name of the loaded rule
            rule (dict): The rule definition from the file.
        """
        self.rule_name = rule_name
        self.rule_index = rule_index
        self.min_retention = min_retention
        self.max_retention = max_retention
        self.applyto = applyto
        self.resource_type = resource_type
        self.resource_ids = resource_ids

    def GenerateRuleViolation(self, buckets_lifecycle, describe):
        return self.rttRuleViolation(
            resource_name=buckets_lifecycle.name,
            resource_type=buckets_lifecycle.type,
            full_name=buckets_lifecycle.full_name,
            rule_name=self.rule_name,
            rule_index=self.rule_index,
            violation_type=VIOLATION_TYPE,
            violation_describe=describe
        )
        
    def GetResource(self):
        """
        Get the resources corresponding to the rule.

        Returns:
           list:  A list of dict (type and ids).
        """
        result = []
        for id in self.resource_ids:
            tmpdict = {}
            tmpdict["type"] = self.resource_type
            tmpdict["ids"] = id
            result.append(tmpdict)
        return result
    

    def is_resource_in_full_name(self, full_name, given_type, given_name):
        """Check a given resource is an ancestor in the full_name.

        Args:
            full_name (str): The full resource name from the model, includes all
                parent resources in the hierarchy to the root organization.
            given_type: The type of the given resource, e.g., bucket
            given_name: The name of the given resource, e.g., some-bucket-name

        Returns:
            bool: True it is in the full_name; otherwise False
        """
        for (resource_type, resource_id) in utils.get_resources_from_full_name(full_name):
            if(resource_type == given_type and resource_id == given_name):
                return True

        return False

    def IsAppliedTo(self, buckets_lifecycle):
        is_rule_apply_to = False
        for r in self.GetResource():
            if self.is_resource_in_full_name(buckets_lifecycle.full_name, r["type"], r["ids"]):
                return True
        return False

    # TODO: The naming is confusing and needs to be fixed in all scanners.
    def find_buckets_violations(self, buckets_lifecycle):
        if(self.IsAppliedTo(buckets_lifecycle) == False):
            return
        
        minretention = self.min_retention
        maxretention = self.max_retention
        exist_match = False
        for lci in buckets_lifecycle.lifecycleitems:
            age = lci.get("condition", {}).get("age", None)
            if age == None:
                continue
            if(minretention != None and age < minretention):
                yield self.GenerateRuleViolation(buckets_lifecycle, "age %d is smaller than the minimum retention %d"%(age,minretention))
                continue
            if(maxretention != None and age > maxretention):
                yield self.GenerateRuleViolation(buckets_lifecycle, "age %d is larger than the maximum retention %d"%(age,maxretention))
                continue
            if(lci.get("condition", {}).has_key("createdBefore") == True):
                continue
            if(lci.get("condition", {}).has_key("matchesStorageClass") == True):
                continue
            if(lci.get("condition", {}).has_key("numNewerVersions") == True):
                continue
            if(lci.get("condition", {}).has_key("isLive") == True):
                continue
            exist_match = True
        if(exist_match == False):
            yield self.GenerateRuleViolation(buckets_lifecycle, "No condition satisfies the rule (min %s, max %s)"%(str(minretention), str(maxretention)))
