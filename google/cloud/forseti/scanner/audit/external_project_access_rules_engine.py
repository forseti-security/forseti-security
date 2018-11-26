# Copyright 2018 The Forseti Security Authors. All rights reserved.
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

"""Rules engine for external project access."""
from collections import namedtuple
import itertools
import re

from google.cloud.forseti.common.gcp_type import resource as resource_mod
from google.cloud.forseti.common.gcp_type import resource_util
from google.cloud.forseti.common.util import logger
from google.cloud.forseti.scanner.audit import errors as audit_errors
from google.cloud.forseti.scanner.audit import base_rules_engine as bre

LOGGER = logger.get_logger(__name__)


class ExternalProjectAccessRulesEngine(bre.BaseRulesEngine):
    """Rules engine for External Project Access."""

    def __init__(self, rules_file_path, snapshot_timestamp=None):
        """Initialize.

        Args:
            rules_file_path (str): file location of rules
            snapshot_timestamp (str): snapshot timestamp. Defaults to None.
                If set, this will be the snapshot timestamp
                used in the engine.
        """
        super(ExternalProjectAccessRulesEngine,
              self).__init__(rules_file_path=rules_file_path)
        self.rule_book = None

    def build_rule_book(self, global_configs=None):
        """Build ExternalProjectAccess rule book from the rules definition file.

        Args:
            global_configs (dict): Inventory configurations.
        """
        self.rule_book = (
            ExternalProjectAccessRuleBook(
                self._load_rule_definitions()))

    # TODO: The naming is confusing and needs to be fixed in all scanners.
    def find_violations(self, user_email,
                        project_ancestry, force_rebuild=False):
        """Determine whether project ancestry violates rules.

        Args:
            user_email (str): The user's e-mail
            project_ancestry (list): List of ancestries which turn
                                     out to a list of resources.
            force_rebuild (bool): Force the rebuild of the rule book

        Returns:
             generator: A generator of rule violations.
        """

        if self.rule_book is None or force_rebuild:
            self.build_rule_book()

        violations = itertools.chain(
            self.rule_book.find_violations(
                user_email, project_ancestry))

        return violations


class ExternalProjectAccessRuleBook(bre.BaseRuleBook):
    """The RuleBook for ExternalProjectAccess resources."""

    # Class variable for matching the ancestor during rule validation
    ancestor_pattern = re.compile(r'^organizations/\d+$|^folders/\d+$')

    def __init__(self, rule_defs=None):
        """Initialization.

        Args:
            rule_defs (dict): rule definitons
        """
        super(ExternalProjectAccessRuleBook, self).__init__()
        self.resource_rules_map = dict()

        if not rule_defs:
            rule_defs = dict(rules=[])

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
        ancestors = self.process_rule(rule_def, rule_index)
        rule = Rule(rule_name=rule_def.get('name'),
                    rule_index=rule_index,
                    rules=ancestors)
        if ancestors not in self.resource_rules_map.keys():
            self.resource_rules_map[rule_index] = rule

    def process_rule(self, rule_def, rule_index):
        """Process a rule.

        Args:
            rule_def (dict): A dictionary containing rule definition
                properties.
            rule_index (int): The index of the rule from the rule definitions.
                Assigned automatically when the rule book is built.

        Returns:
            ancestors: The ancestors as resources defined in the rule
        """
        ancestor_resources = []
        allowed_ancestors = rule_def.get('allowed_ancestors', None)
        self.validate_ancestors(allowed_ancestors, rule_index)

        for allowed_ancestor in allowed_ancestors:
            ancestor_resources.append(
                resource_util.create_resource(
                    allowed_ancestor.split('/')[1],
                    resource_util.type_from_name(allowed_ancestor)))
        return ancestor_resources

    def validate_ancestors(self, ancestors, rule_index):
        """Validate a list of ancestors in a rule.

        Args:
            ancestors (list): The ancestors defined by the rule.
            rule_index (int): The index of the rule from the rule definitions.
                Assigned automatically when the rule book is built.

        """
        for ancestor in ancestors:
            self.validate_ancestor(ancestor, rule_index)

    def validate_ancestor(self, ancestor, rule_index):
        """Validate the ancestor in a rule.

        Args:
            ancestor (str): The ancestor defined by the rule.
            rule_index (int): The index of the rule from the rule definitions.
                Assigned automatically when the rule book is built.

        """

        if not ancestor:
            raise audit_errors.InvalidRulesSchemaError(
                'Missing ancestor in rule {}'.format(rule_index))

        ancestor_result = self.ancestor_pattern.match(ancestor)

        if not ancestor_result:
            message = ('Ancestor in rule {} must start with '
                       '\"organizations/\" or \"folders/\"')
            message.format(rule_index)
            raise audit_errors.InvalidRulesSchemaError(message)

    def find_violations(self, user_email, project_ancestry):
        """Determine whether project ancestry violates rules.

        Args:
            user_email (str): The user's e-mail
            project_ancestry (list): List of ancestries which turn
                                     out to a list of resources.

        Returns:
             list: A list of rule violations.
        """

        rules_violated = []
        for _, rule in self.resource_rules_map.iteritems():
            violation = rule.find_violation(user_email,
                                            project_ancestry)
            # If violation is none, that means a whitelisted rule
            # passed and nothing else matters.  We return no violations
            if violation is None:
                return []

            rules_violated.append(violation)
        return rules_violated


class Rule(object):
    """Rule properties from the rule definition file.

       Also finds violations.
    """

    def __init__(self, rule_name, rule_index, rules):
        """Initialize.

        Args:
            rule_name (str): Name of the loaded rule
            rule_index (int): The index of the rule from the rule definitions
            rules (dict): The ancestor from the rule from the file
        """
        self.rule_name = rule_name
        self.rule_index = rule_index
        self.rules = rules

    # TODO: The naming is confusing and needs to be fixed in all scanners.
    def find_violation(self, user_email, ancestry):
        """Find external project access policy acl violations in the rule book.

        Args:
            user_email (string): The e-mail of the user
            ancestry (dict): The ancestry provided by the scanner

        Return:
            namedtuple: Returns RuleViolation named tuple or None if
                not violated.
        """

        if not [resource for resource in self.rules if resource in ancestry]:

            return self.RuleViolation(
                resource_type=resource_mod.ResourceType.PROJECT,
                resource_id=ancestry[0].id,
                rule_name=self.rule_name,
                rule_index=self.rule_index,
                rule_ancestors=self.rules,
                full_name=ancestry[0].name,
                violation_type='EXTERNAL_PROJECT_ACCESS_VIOLATION',
                member=user_email,
                resource_data=','.join([resource.name for
                                        resource in ancestry]))
        return None
    # Rule violation.
    # resource_type: string
    # resource_id: string
    # rule_name: string
    # rule_index: int
    # violation_type: EXTERNAL_PROJECT_ACCESS_VIOLATION
    # member: string
    # resource_data: list
    RuleViolation = namedtuple('RuleViolation',
                               ['resource_type', 'resource_id',
                                'rule_name', 'rule_index',
                                'rule_ancestors',
                                'full_name',
                                'violation_type',
                                'member',
                                'resource_data'])
