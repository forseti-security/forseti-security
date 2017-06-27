
# Copyright 2017 Google Inc.
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
from google.cloud.security.scanner.audit import base_rules_engine as bre
from google.cloud.security.scanner.audit import errors as audit_errors


# TODO: The next editor must remove this disable and correct issues.
# pylint: disable=missing-type-doc,missing-return-type-doc,missing-return-doc
# pylint: disable=missing-param-doc,missing-yield-doc,differing-param-doc
# pylint: disable=missing-yield-type-doc,redundant-returns-doc


LOGGER = log_util.get_logger(__name__)


# TODO: move this to utils since it's used in more that one engine
def escape_and_globify(pattern_string):
    """Given a pattern string with a glob, create actual regex pattern.

    To require > 0 length glob, change the "*" to ".+". This is to handle
    strings like "*@company.com". (THe actual regex would probably be
    ".*@company.com", except that we don't want to match zero-length
    usernames before the "@".)

    Args:
        pattern_string: The pattern string of which to make a regex.

    Returns:
    The pattern string, escaped except for the "*", which is
    transformed into ".+" (match on one or more characters).
    """

    return '^{}$'.format(re.escape(pattern_string).replace('\\*', '.+'))


class BucketsRulesEngine(bre.BaseRulesEngine):
    """Rules engine for bucket acls"""

    def __init__(self, rules_file_path, snapshot_timestamp=None):
        """Initialize.

        Args:
            rules_file_path: file location of rules
        """
        super(BucketsRulesEngine,
              self).__init__(rules_file_path=rules_file_path)
        self.rule_book = None

    def build_rule_book(self, forseti_configs):
        """Build BucketsRuleBook from the rules definition file.

        forseti_configs (dict): Forseti configurations.
        """
        self.rule_book = BucketsRuleBook(forseti_configs,
                                         self._load_rule_definitions())

    # pylint: disable=arguments-differ
    def find_policy_violations(self, buckets_acls,
                               force_rebuild=False):
        """Determine whether bucket acls violates rules."""
        violations = itertools.chain()
        if self.rule_book is None or force_rebuild:
            self.build_rule_book()
        resource_rules = self.rule_book.get_resource_rules()

        for rule in resource_rules:
            violations = itertools.chain(violations,
                                         rule.\
                                         find_policy_violations(buckets_acls))
        return violations

    def add_rules(self, rules):
        """Add rules to the rule book."""
        if self.rule_book is not None:
            self.rule_book.add_rules(rules)


class BucketsRuleBook(bre.BaseRuleBook):
    """The RuleBook for bucket acls resources."""

    def __init__(self, forseti_configs, rule_defs=None):
        """Initialization.

        Args:
            forseti_configs (dict): Forseti configurations.
            rule_defs: rule definitons
        """
        super(BucketsRuleBook, self).__init__()
        self.resource_rules_map = {}
        if not rule_defs:
            self.rule_defs = {}
        else:
            self.rule_defs = rule_defs
            self.add_rules(rule_defs)

    def add_rules(self, rule_defs):
        """Add rules to the rule book"""
        for (i, rule) in enumerate(rule_defs.get('rules', [])):
            self.add_rule(rule, i)

    def add_rule(self, rule_def, rule_index):
        """Add a rule to the rule book.

        Args:
            rule_def: A dictionary containing rule definition properties.
            rule_index: The index of the rule from the rule definitions.
            Assigned automatically when the rule book is built.

        Raises:

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

        Args:
            resource: The resource to find in the ResourceRules map.

        Returns:
            A list of ResourceRules.
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
            rule_name: Name of the loaded rule
            rule_index: The index of the rule from the rule definitions
            rules: The rules from the file
        """
        self.rule_name = rule_name
        self.rule_index = rule_index
        self.rules = rules

    def find_policy_violations(self, bucket_acl):
        """Find bucket policy acl violations in the rule book.

        Args:
            bucket_acl: Bucket ACL resource

        Returns:
            Returns RuleViolation named tuple
        """
        if self.rules.bucket != '^.+$':
            bucket_bool = re.match(self.rules.bucket, bucket_acl.bucket)
        else:
            bucket_bool = True
        if self.rules.entity != '^.+$':
            entity_bool = re.match(self.rules.entity, bucket_acl.entity)
        else:
            entity_bool = True
        if self.rules.email != '^.+$':
            email_bool = re.match(self.rules.email, bucket_acl.email)
        else:
            email_bool = True
        if self.rules.domain != '^.+$':
            domain_bool = re.match(self.rules.domain, bucket_acl.domain)
        else:
            domain_bool = True
        if self.rules.role != '^.+$':
            role_bool = re.match(self.rules.role, bucket_acl.role)
        else:
            role_bool = True

        should_raise_violation = (
            (bucket_bool is not None and bucket_bool) and
            (entity_bool is not None and entity_bool) and
            (email_bool is not None and email_bool) and
            (domain_bool is not None and domain_bool) and
            (role_bool is not None and role_bool))

        if should_raise_violation:
            yield self.RuleViolation(
                resource_type='project',
                resource_id=bucket_acl.project_number,
                rule_name=self.rule_name,
                rule_index=self.rule_index,
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
                                'rule_index', 'violation_type', 'role',
                                'entity', 'email', 'domain', 'bucket'])
