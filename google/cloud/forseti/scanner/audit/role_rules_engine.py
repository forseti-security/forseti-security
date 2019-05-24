# Copyright 2019 The Forseti Security Authors. All rights reserved.
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
from builtins import object
import collections
import itertools
import threading
import json

from google.cloud.forseti.common.util import logger
from google.cloud.forseti.common.util import relationship
from google.cloud.forseti.scanner.audit import base_rules_engine as bre
from google.cloud.forseti.scanner.audit import errors as audit_errors


LOGGER = logger.get_logger(__name__)

VIOLATION_TYPE = 'CUSTOM_ROLE_VIOLATION'

RuleViolation = collections.namedtuple(
    'RuleViolation',
    ['resource_name', 'resource_type', 'full_name', 'rule_name',
     'rule_index', 'violation_type', 'violation_data', 'resource_data',
     'resource_id'])


class RoleRulesEngine(bre.BaseRulesEngine):
    """Rules engine for roles."""

    def __init__(self, rules_file_path, snapshot_timestamp=None):
        """Initialize.

        Args:
            rules_file_path (str): file location of rules
            snapshot_timestamp (str): snapshot timestamp. Defaults to None.
                If set, this will be the snapshot timestamp
                used in the engine.
        """
        super(RoleRulesEngine,
              self).__init__(rules_file_path=rules_file_path)
        self.rule_book = None

    def build_rule_book(self, global_configs=None):
        """Build RoleRuleBook from the rules definition file.

        Args:
            global_configs (dict): Global configurations.
        """
        self.rule_book = RoleRuleBook(self._load_rule_definitions())

    def find_violations(self, role, force_rebuild=False):
        """Determine whether the role violates rules.

        Args:
            role (Role): Role to be tested.
            force_rebuild (bool): If True, rebuilds the rule book. This will
                reload the rules definition file and add the rules to the book.

        Returns:
             generator: A generator of rule violations.
        """
        if self.rule_book is None or force_rebuild:
            self.build_rule_book()

        violations = itertools.chain()
        rules = self.rule_book.get_rule_by_role_name(role.id)
        for rule in rules:
            violations = itertools.chain(
                violations,
                rule.find_violations(role))

        return set(violations)


class RoleRuleBook(bre.BaseRuleBook):
    """The RuleBook for Role resources."""

    def __init__(self, rule_defs=None):
        """Initialization.

        Args:
            rule_defs (dict): rule definitons
        """
        super(RoleRuleBook, self).__init__()
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
        if 'name' not in rule_def:
            raise audit_errors.InvalidRulesSchemaError(
                'Lack of role_name in rule {}'.format(rule_index))
        if 'role_name' not in rule_def:
            raise audit_errors.InvalidRulesSchemaError(
                'Lack of role_name in rule {}'.format(rule_index))
        role_name = rule_def['role_name']
        if 'permissions' not in rule_def:
            raise audit_errors.InvalidRulesSchemaError(
                'Lack of permissions in rule {}'.format(rule_index))
        if 'resource' not in rule_def:
            raise audit_errors.InvalidRulesSchemaError(
                'Lack of resource in rule {}'.format(rule_index))
        res = rule_def['resource']

        rule = Rule(rule_index=rule_index,
                    rule_name=rule_def['name'],
                    permissions=rule_def['permissions'],
                    res=res)

        if role_name not in self.rules_map:
            self.rules_map[role_name] = [rule]
        else:
            self.rules_map[role_name].append(rule)

    def get_rule_by_role_name(self, role_name):
        """Get the rule of a given role.

        Args:
            role_name (str): Name of a role.
        Returns:
            list: Rule list of the given role.
        """
        return self.rules_map.get(role_name, [])


class Rule(object):
    """Rule properties from the rule definition file. Also finds violations."""

    def __init__(self, rule_index, rule_name, permissions, res):
        """Initialize.

        Args:
            rule_index (int): The index of the rule.
            rule_name (str): Name of the rule.
            permissions (int): Expected permissions of the role.
            res (dict): Parent resource of the role that should obey the rule.
        """
        self.rule_name = rule_name
        self.rule_index = rule_index
        self.permissions = permissions[:]
        self.res_types = res[:]

        for index, res_item in enumerate(self.res_types):
            if 'type' not in res_item:
                raise audit_errors.InvalidRulesSchemaError(
                    'Lack of resource:type in rule {}'.format(rule_index))
            if res_item['type'] not in [
                    'organization', 'folder', 'project', 'role']:
                raise audit_errors.InvalidRulesSchemaError(
                    'Wrong resource:type {} in rule {}'.format(
                        res_item['type'], rule_index))
            if 'resource_ids' not in res_item:
                raise audit_errors.InvalidRulesSchemaError(
                    'Lack of resource:resource_ids in rule {}'.format(
                        rule_index))

            if '*' in res_item['resource_ids']:
                self.res_types[index]['resource_ids'] = ['*']

    def generate_violation(self, role):
        """Generate a violation.

        Args:
            role (Role): The role that triggers the violation.
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

        def find_violations_in_role(role):
            """Get a generator for violations.

            Args:
                role (role): Find violation from the role.
            Returns:
                RuleViolation: All violations of the role breaking the rule.
            """
            resource_ancestors = (relationship.find_ancestors(
                role, role.full_name))

            violations = itertools.chain()
            for related_resources in resource_ancestors:
                violations = itertools.chain(
                    violations,
                    self.find_violations_by_ancestor(related_resources, role))
            return violations

        if res.type == 'role':
            return find_violations_in_role(res)
        raise ValueError(
            'only role is supported.'
        )

    def find_violations_by_ancestor(self, ancestor, role):
        """Get a generator on a given ancestor of the role.

        Args:
            role (role): Role to find violation from.
            ancestor (Resource): Ancestor of the role or the role itself.
        Yields:
            RuleViolation: All violations of the role breaking the rule.
        """
        for res in self.res_types:
            if ancestor.type != res['type']:
                continue
            if '*' in res['resource_ids']:
                if set(role.get_permissions()) != set(self.permissions):
                    yield self.generate_violation(role)
            else:
                for res_id in res['resource_ids']:
                    if res_id == ancestor.id:
                        if set(role.get_permissions()) != set(self.permissions):
                            yield self.generate_violation(role)
