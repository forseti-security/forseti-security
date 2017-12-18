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

"""Rules engine for Bucket acls"""
from collections import namedtuple
import itertools
import re

# pylint: disable=line-too-long
from google.cloud.security.common.gcp_type import bucket_access_controls as bkt_acls
# pylint: enable=line-too-long
from google.cloud.security.common.util import log_util
from google.cloud.security.common.util.regex_util import escape_and_globify
from google.cloud.security.scanner.audit import base_rules_engine as bre
from google.cloud.security.scanner.audit import errors as audit_errors


LOGGER = log_util.get_logger(__name__)


class BucketsRulesEngine(bre.BaseRulesEngine):
    """Rules engine for bucket acls"""

    def __init__(self, rules_file_path, snapshot_timestamp=None):
        """Initialize.

        Args:
            rules_file_path (str): file location of rules
            snapshot_timestamp (str): snapshot timestamp. Defaults to None.
                If set, this will be the snapshot timestamp
                used in the engine.
        """
        super(BucketsRulesEngine,
              self).__init__(rules_file_path=rules_file_path)
        self.rule_book = None

    def build_rule_book(self, global_configs=None):
        """Build BucketsRuleBook from the rules definition file.

        Args:
            global_configs (dict): Global configurations.
        """
        self.rule_book = BucketsRuleBook(self._load_rule_definitions())

    # TODO: The naming is confusing and needs to be fixed in all scanners.
    def find_policy_violations(self, buckets_acls,
                               force_rebuild=False):
        """Determine whether bucket acls violates rules.

        Args:
            buckets_acls (BucketAccessControls): Object containing ACL
                data
            force_rebuild (bool): If True, rebuilds the rule book. This will
                reload the rules definition file and add the rules to the book.

        Returns:
             generator: A generator of rule violations.
        """
        violations = itertools.chain()
        if self.rule_book is None or force_rebuild:
            self.build_rule_book()
        resource_rules = self.rule_book.get_resource_rules()

        for rule in resource_rules:
            violations = itertools.chain(
                violations,
                rule.find_policy_violations(buckets_acls))
        return violations

    def add_rules(self, rules):
        """Add rules to the rule book.

        Args:
            rules (dict): rule definitions dictionary
        """
        if self.rule_book is not None:
            self.rule_book.add_rules(rules)


class BucketsRuleBook(bre.BaseRuleBook):
    """The RuleBook for bucket acls resources."""

    def __init__(self, rule_defs=None):
        """Initialization.

        Args:
            rule_defs (dict): rule definitons
        """
        super(BucketsRuleBook, self).__init__()
        self.resource_rules_map = {}
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
        resources = rule_def.get('resource')

        for resource in resources:
            resource_ids = resource.get('resource_ids')

            if not resource_ids or len(resource_ids) < 1:
                raise audit_errors.InvalidRulesSchemaError(
                    'Missing resource ids in rule {}'.format(rule_index))

            bucket = rule_def.get('bucket')
            entity = rule_def.get('entity')
            email = rule_def.get('email')
            domain = rule_def.get('domain')
            role = rule_def.get('role')

            if (bucket is None) or (entity is None) or (email is None) or\
               (domain is None) or (role is None):
                raise audit_errors.InvalidRulesSchemaError(
                    'Faulty rule {}'.format(rule_def.get('name')))

            rule_def_resource = bkt_acls.BucketAccessControls(
                escape_and_globify(bucket),
                escape_and_globify(entity),
                escape_and_globify(email),
                escape_and_globify(domain),
                escape_and_globify(role.upper()))

            rule = Rule(rule_name=rule_def.get('name'),
                        rule_index=rule_index,
                        rules=rule_def_resource)

            resource_rules = self.resource_rules_map.get(rule_index)

            if not resource_rules:
                self.resource_rules_map[rule_index] = rule

    def get_resource_rules(self):
        """Get all the resource rules for (resource, RuleAppliesTo.*).

        Returns:
           list:  A list of ResourceRules.
        """
        resource_rules = []

        for resource_rule in self.resource_rules_map:
            resource_rules.append(self.resource_rules_map[resource_rule])

        return resource_rules


class Rule(object):
    """Rule properties from the rule definition file.
    Also finds violations.
    """

    def __init__(self, rule_name, rule_index, rules):
        """Initialize.

        Args:
            rule_name (str): Name of the loaded rule
            rule_index (int): The index of the rule from the rule definitions
            rules (dict): The rules from the file
        """
        self.rule_name = rule_name
        self.rule_index = rule_index
        self.rules = rules

    # TODO: The naming is confusing and needs to be fixed in all scanners.
    def find_policy_violations(self, bucket_acl):
        """Find bucket policy acl violations in the rule book.

        Args:
            bucket_acl (BucketAccessControls): Bucket ACL resource

        Yields:
            namedtuple: Returns RuleViolation named tuple
        """
        is_bucket_violated = True
        is_entity_violated = True
        is_email_violated = True
        is_domain_violated = True
        is_role_violated = True

        is_bucket_violated = re.match(
            self.rules.bucket, bucket_acl.bucket, re.IGNORECASE)

        is_entity_violated = re.match(
            self.rules.entity, bucket_acl.entity, re.IGNORECASE)

        is_email_violated = re.match(
            self.rules.email, bucket_acl.email, re.IGNORECASE)

        is_domain_violated = re.match(
            self.rules.domain, bucket_acl.domain, re.IGNORECASE)

        is_role_violated = re.match(
            self.rules.role, bucket_acl.role, re.IGNORECASE)

        should_raise_violation = (
            (is_bucket_violated is not None and is_bucket_violated) and
            (is_entity_violated is not None and is_entity_violated) and
            (is_email_violated is not None and is_email_violated) and
            (is_domain_violated is not None and is_domain_violated) and
            (is_role_violated is not None and is_role_violated))

        if should_raise_violation:
            yield self.RuleViolation(
                resource_type='bucket',
                resource_id=bucket_acl.project_number,
                rule_name=self.rule_name,
                rule_index=self.rule_index,
                new_violation=1,
                violation_type='BUCKET_VIOLATION',
                role=bucket_acl.role,
                entity=bucket_acl.entity,
                email=bucket_acl.email,
                domain=bucket_acl.domain,
                bucket=bucket_acl.bucket)

    # Rule violation.
    # resource_type: string
    # resource_id: string
    # rule_name: string
    # rule_index: int
    # violation_type: BUCKET_VIOLATION
    # role: string
    # entity: string
    # email: string
    # domain: string
    # bucket: string
    RuleViolation = namedtuple('RuleViolation',
                               ['resource_type', 'resource_id', 'rule_name',
                                'rule_index', 'new_violation', 'violation_type',
                                'role', 'entity', 'email', 'domain', 'bucket'])
