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

"""Rules engine for CloudSQL acls"""
from collections import namedtuple
import itertools
import re

# pylint: disable=line-too-long
from google.cloud.security.common.gcp_type import cloudsql_access_controls as csql_acls
# pylint: enable=line-too-long
from google.cloud.security.common.util import log_util
from google.cloud.security.common.util.regex_util import escape_and_globify
from google.cloud.security.scanner.audit import base_rules_engine as bre
from google.cloud.security.scanner.audit import errors as audit_errors


LOGGER = log_util.get_logger(__name__)


class CloudSqlRulesEngine(bre.BaseRulesEngine):
    """Rules engine for CloudSQL acls"""

    def __init__(self, rules_file_path, snapshot_timestamp=None):
        """Initialize.

        Args:
            rules_file_path (str): file location of rules
            snapshot_timestamp (str): snapshot timestamp. Defaults to None.
                If set, this will be the snapshot timestamp
                used in the engine.
        """
        super(CloudSqlRulesEngine,
              self).__init__(rules_file_path=rules_file_path)
        self.rule_book = None

    def build_rule_book(self, global_configs=None):
        """Build CloudSQLRuleBook from the rules definition file.

        Args:
            global_configs (dict): Global configurations.
        """
        self.rule_book = CloudSqlRuleBook(self._load_rule_definitions())

    # TODO: The naming is confusing and needs to be fixed in all scanners.
    def find_policy_violations(self, cloudsql_acls,
                               force_rebuild=False):
        """Determine whether CloudSQL acls violates rules.

        Args:
            cloudsql_acls (CloudsqlAccessControls): Object containing
                ACL data
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
                                         find_policy_violations(cloudsql_acls))
        return violations

    def add_rules(self, rules):
        """Add rules to the rule book.

        Args:
            rules (dict): rule definitions dictionary
        """
        if self.rule_book is not None:
            self.rule_book.add_rules(rules)


class CloudSqlRuleBook(bre.BaseRuleBook):
    """The RuleBook for CloudSQL acls resources."""

    def __init__(self, rule_defs=None):
        """Initialization.

        Args:
            rule_defs (dict): rule definitons
        """
        super(CloudSqlRuleBook, self).__init__()
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

            instance_name = rule_def.get('instance_name')
            authorized_networks = rule_def.get('authorized_networks')
            ssl_enabled = rule_def.get('ssl_enabled')

            if (instance_name is None) or (authorized_networks is None) or\
             (ssl_enabled is None):
                raise audit_errors.InvalidRulesSchemaError(
                    'Faulty rule {}'.format(rule_def.get('name')))

            rule_def_resource = csql_acls.CloudSqlAccessControl(
                escape_and_globify(instance_name),
                escape_and_globify(authorized_networks),
                ssl_enabled)

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

    # TODO: The naming is confusing and needs to be fixed in all scanners.
    def find_policy_violations(self, cloudsql_acl):
        """Find CloudSQL policy acl violations in the rule book.

        Args:
            cloudsql_acl (CloudsqlAccessControls): CloudSQL ACL resource

        Yields:
            namedtuple: Returns RuleViolation named tuple
        """
        filter_list = []
        is_instance_name_violated = True
        is_authorized_networks_violated = True
        is_ssl_enabled_violated = True

        is_instance_name_violated = re.match(self.rules.instance_name,
                                             cloudsql_acl.instance_name)

        authorized_networks_regex = re.compile(self.rules.authorized_networks)
        filter_list = [
            net for net in cloudsql_acl.authorized_networks if\
            authorized_networks_regex.match(net)
        ]

        is_authorized_networks_violated = bool(filter_list)

        is_ssl_enabled_violated = (self.rules.ssl_enabled ==\
                                   cloudsql_acl.ssl_enabled)

        should_raise_violation = (
            (is_instance_name_violated is not None and
             is_instance_name_violated) and
            (is_authorized_networks_violated is not None and
             is_authorized_networks_violated) and
            (is_ssl_enabled_violated is not None and is_ssl_enabled_violated))

        if should_raise_violation:
            yield self.RuleViolation(
                resource_type='cloudsql',
                resource_id=cloudsql_acl.project_number,
                rule_name=self.rule_name,
                rule_index=self.rule_index,
                new_violation=1,
                violation_type='CLOUD_SQL_VIOLATION',
                instance_name=cloudsql_acl.instance_name,
                authorized_networks=cloudsql_acl.authorized_networks,
                ssl_enabled=cloudsql_acl.ssl_enabled)

    # Rule violation.
    # resource_type: string
    # resource_id: string
    # rule_name: string
    # rule_index: int
    # violation_type: CLOUD_SQL_VIOLATION
    # instance_name: string
    # authorized_networks: string
    # ssl_enabled: string
    RuleViolation = namedtuple('RuleViolation',
                               ['resource_type', 'resource_id', 'rule_name',
                                'rule_index', 'new_violation', 'violation_type',
                                'instance_name', 'authorized_networks',
                                'ssl_enabled'])
