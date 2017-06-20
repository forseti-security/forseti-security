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

"""Rules engine for Big Query data sets"""
from collections import namedtuple
import itertools
import re

# pylint: disable=line-too-long
from google.cloud.security.common.gcp_type import bigquery_access_controls as bq_acls
# pylint: enable=line-too-long
from google.cloud.security.common.util import log_util
from google.cloud.security.scanner.audit import base_rules_engine as bre
from google.cloud.security.scanner.audit import errors as audit_errors

LOGGER = log_util.get_logger(__name__)


# TODO: move this to utils since it's used in more that one engine
def escape_and_globify(pattern_string):
    """Given a pattern string with a glob, create actual regex pattern.

    To require > 0 length glob, change the "*" to ".+". This is to handle
    strings like "*@company.com". (THe actual regex would probably be
    ".*@company.com", except that we don't want to match zero-length
    usernames before the "@".)

    Args:
        pattern_string (str): The pattern string of which to make a regex.

    Returns:
        str: The pattern string, escaped except for the "*", which is
        transformed into ".+" (match on one or more characters).
    """

    return '^{}$'.format(re.escape(pattern_string).replace('\\*', '.+'))


class BigqueryRulesEngine(bre.BaseRulesEngine):
    """Rules engine for Big Query data sets"""

    def __init__(self, rules_file_path, snapshot_timestamp=None):
        """Initialize.

        Args:
            rules_file_path (str): file location of rules
            snapshot (:obj:`str`, optional): snapshot timestamp.
                Defaults to None. If set, this will be the snapshot timestamp
                used in the engine.
        """
        super(BigqueryRulesEngine,
              self).__init__(rules_file_path=rules_file_path)
        self.rule_book = None

    def build_rule_book(self):
        """Build BigqueryRuleBook from the rules definition file."""
        self.rule_book = BigqueryRuleBook(self._load_rule_definitions())

    # pylint: disable=arguments-differ
    def find_policy_violations(self, bq_datasets,
                               force_rebuild=False):
        """Determine whether Big Query datasets violate rules.

        Args:
            bq_datasets (:obj:`BigqueryAccessControls`): Object containing ACL
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
            violations = itertools.chain(violations,
                                         rule.\
                                         find_policy_violations(bq_datasets))
        return violations

    def add_rules(self, rules):
        """Add rules to the rule book.

        Args:
            rules (dict): rule definitions dictionary
        """
        if self.rule_book is not None:
            self.rule_book.add_rules(rules)


class BigqueryRuleBook(bre.BaseRuleBook):
    """The RuleBook for Big Query dataset resources."""

    def __init__(self, rule_defs=None):
        """Initialization.

        Args:
            rule_defs (dict): rule definitons dictionary
        """
        super(BigqueryRuleBook, self).__init__()
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

        resources = rule_def.get('resource')

        for resource in resources:
            resource_ids = resource.get('resource_ids')

            if not resource_ids or len(resource_ids) < 1:
                raise audit_errors.InvalidRulesSchemaError(
                    'Missing resource ids in rule {}'.format(rule_index))

            dataset_id = rule_def.get('dataset_id')
            special_group = rule_def.get('special_group')
            user_email = rule_def.get('user_email')
            domain = rule_def.get('domain')
            group_email = rule_def.get('group_email')
            role = rule_def.get('role')

            if (dataset_id is None) or (special_group is None) or\
               (user_email is None) or (domain is None) or\
               (group_email is None) or (role is None):
                raise audit_errors.InvalidRulesSchemaError(
                    'Faulty rule {}'.format(rule_def.get('name')))

            rule_def_resource = bq_acls.BigqueryAccessControls(
                escape_and_globify(dataset_id),
                escape_and_globify(special_group),
                escape_and_globify(user_email),
                escape_and_globify(domain),
                escape_and_globify(group_email),
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
            list: A list of ResourceRules.
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

    def find_policy_violations(self, bigquery_acl):
        """Find BigQuery acl violations in the rule book.

        Args:
            bigquery_acl (:obj:`BigqueryAccessControls`): BigQuery ACL resource

        Returns:
            namedtuple: Returns RuleViolation named tuple
        """
        if self.rules.dataset_id != '^.+$':
            dataset_id_bool = re.match(self.rules.dataset_id,
                                       bigquery_acl.dataset_id)
        else:
            dataset_id_bool = True
        if self.rules.special_group != '^.+$':
            special_group_bool = re.match(self.rules.special_group,
                                          bigquery_acl.special_group)
        else:
            special_group_bool = True
        if self.rules.user_email != '^.+$':
            user_email_bool = re.match(self.rules.user_email,
                                       bigquery_acl.user_email)
        else:
            user_email_bool = True
        if self.rules.domain != '^.+$':
            domain_bool = re.match(self.rules.domain, bigquery_acl.domain)
        else:
            domain_bool = True
        if self.rules.group_email != '^.+$':
            group_email_bool = re.match(self.rules.group_email,
                                        bigquery_acl.group_email)
        else:
            group_email_bool = True
        if self.rules.role != '^.+$':
            role_bool = re.match(self.rules.role, bigquery_acl.role)
        else:
            role_bool = True

        should_raise_violation = (
            (dataset_id_bool is not None and dataset_id_bool) and
            (special_group_bool is not None and special_group_bool) and
            (user_email_bool is not None and user_email_bool) and
            (domain_bool is not None and domain_bool) and
            (group_email_bool is not None and group_email_bool) and
            (role_bool is not None and role_bool))

        if should_raise_violation:
            yield self.RuleViolation(
                resource_type='project',
                resource_id=bigquery_acl.project_id,
                rule_name=self.rule_name,
                rule_index=self.rule_index,
                violation_type='BIGQUERY_VIOLATION',
                dataset_id=bigquery_acl.dataset_id,
                role=bigquery_acl.role,
                special_group=bigquery_acl.special_group,
                user_email=bigquery_acl.user_email,
                domain=bigquery_acl.domain,
                group_email=bigquery_acl.group_email)

    # Rule violation.
    # resource_type: string
    # resource_id: string
    # rule_name: string
    # rule_index: int
    # violation_type: BIGQUERY_VIOLATION
    # dataset_id: string
    # role: string
    # special_group: string
    # user_email: string
    # domain: string
    # group_email: string
    RuleViolation = namedtuple('RuleViolation',
                               ['resource_type', 'resource_id', 'rule_name',
                                'rule_index', 'violation_type', 'dataset_id',
                                'role', 'special_group', 'user_email',
                                'domain', 'group_email'])
