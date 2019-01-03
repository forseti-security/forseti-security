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

"""Rules engine for Roles."""
import collections
import itertools
import threading
import json

from google.cloud.forseti.common.util import logger
from google.cloud.forseti.scanner.audit import base_rules_engine as bre
from google.cloud.forseti.scanner.audit import errors as audit_errors


LOGGER = logger.get_logger(__name__)

VIOLATION_TYPE = 'ROLE_PERMISSION_VIOLATION'

RuleViolation = collections.namedtuple(
    'RuleViolation',
    ['resource_name', 'resource_type', 'full_name', 'rule_name',
     'rule_index', 'violation_type', 'violation_data', 'resource_data',
     'resource_id'])


class RolePermissionRulesEngine(bre.BaseRulesEngine):
    """Rules engine for roles."""

    def __init__(self, rules_file_path, snapshot_timestamp=None):
        """Initialize.

        Args:
            rules_file_path (str): file location of rules
            snapshot_timestamp (str): snapshot timestamp. Defaults to None.
                If set, this will be the snapshot timestamp
                used in the engine.
        """
        super(RolePermissionRulesEngine,
              self).__init__(rules_file_path=rules_file_path)
        self.rule_book = None

    def build_rule_book(self, global_configs=None):
        """Build RolePermissionRuleBook from the rules definition file.

        Args:
            global_configs (dict): Global configurations.
        """
        self.rule_book = RolePermissionRuleBook(self._load_rule_definitions())

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
        rule = self.rule_book.get_rule_by_role_name(resource.id)
        violations = itertools.chain(
            violations,
            rule.find_violations(resource))

        return set(violations)


class RolePermissionRuleBook(bre.BaseRuleBook):
    """The RuleBook for Retention resources."""

    def __init__(self, rule_defs=None):
        """Initialization.

        Args:
            rule_defs (dict): rule definitons
        """
        super(RolePermissionRuleBook, self).__init__()
        self._rules_sema = threading.BoundedSemaphore(value=1)

        self.rules_map = {}
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
        if 'role_id' not in rule_def:
            raise audit_errors.InvalidRulesSchemaError(
                'Lack of role_id in rule {}'.format(rule_index))
        role_id = rule_def['role_id']

        if role_id in self.rules_map:
            raise audit_errors.InvalidRulesSchemaError(
                'Duplicate role_id in rule {}'.format(rule_index))

        if 'permissions' not in rule_def:
            raise audit_errors.InvalidRulesSchemaError(
                'Lack of permissions in rule {}'.format(rule_index))
        permissions = rule_def['permissions']

        rule = Rule(rule_index=rule_index,
                    role_name=role_id,
                    permissions=permissions)

        self.rules_map[role_id] = rule

    def get_rule_by_role_name(self, role_name):
        """Get the rule of a given role.

        Args:
            role_name (str): Name of a role.
        Returns:
            Rule: Rule of the given role.
        """
        return self.rules_map.get(role_name)


def create_rule_name_by_role_name(role_name):
    """Create a rule name based on the name of a given role.

    Args:
        role_name (str): Name of a role.
    Returns:
        str: Name of the rule.
    """
    return 'Permission Rule of ' + role_name


class Rule(object):
    """Rule properties from the rule definition file. Also finds violations."""

    def __init__(self, rule_index, role_name, permissions):
        """Initialize.

        Args:
            rule_index (int): The index of the rule.
            role_name(str): Name of the role.
            permissions(int): Expected permissions of the role.
        """
        self.rule_name = create_rule_name_by_role_name(role_name)
        self.rule_index = rule_index
        self.permissions = permissions[:]

    def generate_violation(self, role):
        """Generate a violation.

        Args:
            role (TODOTODO): The role that triggers the violation.
        Returns:
            RuleViolation: The violation.
        """
        permissions = role.get_permissions()
        permissions_str = json.dumps(permissions)

        return RuleViolation(
            resource_name=role.name,
            resource_id=role.id,
            resource_type=role.type,
            full_name=role.full_name,
            rule_name=self.rule_name,
            rule_index=self.rule_index,
            violation_type=VIOLATION_TYPE,
            violation_data=permissions_str,
            resource_data=role.data,
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

        if res.type == 'role':
            return self.find_violations_in_role(res)
        raise ValueError(
            'only role is supported.'
        )

    def find_violations_in_role(self, role):
        """Get a generator for violations.

        Args:
            role (role): Find violation from the role.
        Yields:
            RuleViolation: All violations of the role breaking the rule.
        """

        if set(role.get_permissions()) != set(self.permissions):
            yield self.generate_violation(role)
