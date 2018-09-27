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

from google.cloud.forseti.common.util import logger
from google.cloud.forseti.common.util.regular_exp import escape_and_globify
from google.cloud.forseti.scanner.audit import base_rules_engine as bre
from google.cloud.forseti.scanner.audit import errors as audit_errors


LOGGER = logger.get_logger(__name__)

VIOLATION_TYPE = 'BUCKET_RETENTION_VIOLATION'


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


    # TODO: The naming is confusing and needs to be fixed in all scanners.
    def find_buckets_violations(self, buckets_lifecycle, force_rebuild=False):
        """Determine whether bucket lifecycle violates rules.

        Args:
            buckets_lifecycle : Object containing lifecycle
                data
            force_rebuild (bool): If True, rebuilds the rule book. This will
                reload the rules definition file and add the rules to the book.

        Returns:
             generator: A generator of rule violations.
        """

        violations = itertools.chain()
        if self.rule_book is None or force_rebuild:
            self.build_rule_book()
        resource_rules = self.rule_book.get_resource_rules("bucket")

        for rule in resource_rules:
            violations = itertools.chain(
                violations,
                rule.find_buckets_violations(buckets_lifecycle))
            break
        return set(violations)

    def add_rules(self, rules):
        """Add rules to the rule book.

        Args:
            rules (dict): rule definitions dictionary
        """
        if self.rule_book is not None:
            self.rule_book.add_rules(rules)


class RetentionRuleBook(bre.BaseRuleBook):
    """The RuleBook for Retention resources."""

    bucket_supported_resource_types = frozenset([
        'project',
        'folder',
        'bucket',
        'organization',
    ])

    supported_rule_applies_to = frozenset([
        'bucket',
    ])

    def __init__(self, rule_defs=None):
        """Initialization.

        Args:
            rule_defs (dict): rule definitons
        """
        super(RetentionRuleBook, self).__init__()
        self._rules_sema = threading.BoundedSemaphore(value=1)

        self.resource_rules_map = {
            applies_to: []
            for applies_to in self.supported_rule_applies_to}
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
            #print rule
            self.add_rule(rule, i)
        print "finish add rule\n"

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
                    'Lack of applies_to in rule {}'.format(i))
            if type(applies_to).__name__ != "list":
                raise audit_errors.InvalidRulesSchemaError(
                    'Miss dash (-) near applies_to in rule {}'.format(rule_index))
            
            minimum_retention = rule_def.get("minimum_retention", None)
            maximum_retention = rule_def.get("maximum_retention", None)
            if minimum_retention == None and maximum_retention == None:
                raise audit_errors.InvalidRulesSchemaError(
                    'Lack of minimum and maximum retention in rule {}'.format(i))
            elif minimum_retention != None and maximum_retention != None:
                if minimum_retention > maximum_retention:
                    raise audit_errors.InvalidRulesSchemaError(
                        'minimum_retention larger than maximum_retention in rule {}'.format(i))
            
            applies_to_history = {}
            for appto in applies_to:
                if applies_to_history.has_key(appto):
                    raise audit_errors.InvalidRulesSchemaError(
                        'Duplicate applies_to in rule {}'.format(i))
                applies_to_history[appto] = True
                
                if appto == "bucket":
                    self.add_bucket_rule(appto, rule_def, rule_index)
        finally:
            self._rules_sema.release()

    def add_bucket_rule(self, applies_to, rule_def, rule_index):
        """Add a rule to the rule book.

        Args:
            rule_def (dict): A dictionary containing rule definition
                properties.
            rule_index (int): The index of the rule from the rule definitions.
                Assigned automatically when the rule book is built.
        """
        print "add_rule", rule_def
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
        
        rule = Rule(rule_name=rule_def.get('name'),
                            rule_index=rule_index,
                            rule=rule_def)

        #print type(self.resource_rules_map), type(self.resource_rules_map[applies_to]), self.resource_rules_map[applies_to]
        self.resource_rules_map[applies_to].append(rule)
        #print type(self.resource_rules_map), type(self.resource_rules_map[applies_to]), self.resource_rules_map[applies_to]

        

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

    def __init__(self, rule_name, rule_index, rule):
        """Initialize.

        Args:
            rule_name (str): Name of the loaded rule
            rule (dict): The rule definition from the file.
        """
        self.rule_name = rule_name
        self.rule_index = rule_index
        self.rule = rule

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


    def GetMinRetention(self):
        return self.rule.get("minimum_retention",None)
    def GetMaxRetention(self):
        return self.rule.get("maximum_retention",None)
    def GetResource(self):
        res = self.rule.get("resource",None)
        if(res == None):
            return None
        result = []
        for r in res:
            tmpdict = {}
            tmpdict["type"] = r.get("type", "")
            tmpdict["ids"] = r.get("resource_ids", [])
            result.append(tmpdict)
        return result
    def IsAppliedTo(self, buckets_lifecycle):
        is_rule_apply_to = False
        for r in self.GetResource():
            for rid in r["ids"]:
                if resource_util.is_an_ancestor_of(buckets_lifecycle.full_name, r["type"], rid):
                    return True
        return False

    # TODO: The naming is confusing and needs to be fixed in all scanners.
    def find_buckets_violations(self, buckets_lifecycle):
        if(self.IsAppliedTo(buckets_lifecycle) == False):
            return
        
        minretention = self.GetMinRetention()
        maxretention = self.GetMaxRetention()
        exist_match = False
        for lci in buckets_lifecycle.lifecycleitems:
            print lci
            age = lci.get("condition", {}).get("age", None)
            if age == None:
                continue
            if(minretention != None and age < minretention):
                yield self.GenerateRuleViolation(buckets_lifecycle, "age too small")
                continue
            if(maxretention != None and age > maxretention):
                yield self.GenerateRuleViolation(buckets_lifecycle, "age too big")
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
            yield self.GenerateRuleViolation(buckets_lifecycle, "No match condition")
            
            


        

        

        

        

