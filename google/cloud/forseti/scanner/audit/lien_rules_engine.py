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

"""Rules engine for Liens."""
import collections

from google.cloud.forseti.common.gcp_type import resource_util
from google.cloud.forseti.common.util import logger
from google.cloud.forseti.common.util import relationship
from google.cloud.forseti.scanner.audit import base_rules_engine
from google.cloud.forseti.scanner.audit import errors

LOGGER = logger.get_logger(__name__)


RuleViolation = collections.namedtuple(
    'RuleViolation',
    ['resource_id', 'resource_name', 'resource_type', 'full_name', 'rule_index',
     'rule_name', 'violation_type', 'resource_data']
)


class LienRulesEngine(base_rules_engine.BaseRulesEngine):
    """Rules engine for Liens."""

    def __init__(self, rules_file_path, snapshot_timestamp=None):
        """Initialize.

        Args:
            rules_file_path (str): file location of rules
            snapshot_timestamp (str): snapshot timestamp. Defaults to None.
                If set, this will be the snapshot timestamp
                used in the engine.
        """
        super(LienRulesEngine, self).__init__(rules_file_path=rules_file_path)
        self.rule_book = None

    def build_rule_book(self, global_configs=None):
        """Build LienRuleBook from the rules definition file.

        Args:
            global_configs (dict): Global configurations.
        """
        self.rule_book = LienRuleBook(self._load_rule_definitions())

    def find_violations(self, parent_resource, liens, force_rebuild=False):
        """Determine whether Big Query datasets violate rules.

        Args:
            parent_resource (Resource): parent resource the lien belongs to.
            liens (List[Lien]): liens to find violations for.
            force_rebuild (bool): If True, rebuilds the rule book. This will
                reload the rules definition file and add the rules to the book.

        Returns:
             generator: A generator of rule violations.
        """
        if self.rule_book is None or force_rebuild:
            self.build_rule_book()

        violations = self.rule_book.find_violations(parent_resource, liens)
        return violations

    def add_rules(self, rule_defs):
        """Add rules to the rule book.

        Args:
            rule_defs (dict): rule definitions dictionary
        """
        if self.rule_book is not None:
            self.rule_book.add_rules(rule_defs)


class LienRuleBook(base_rules_engine.BaseRuleBook):
    """The RuleBook for Lien resources."""

    def __init__(self, rule_defs=None):
        """Initialization.

        Args:
            rule_defs (dict): rule definitons dictionary.
        """
        super(LienRuleBook, self).__init__()
        self.resource_to_rules = collections.defaultdict(list)
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
        resources = rule_def.get('resource')
        if not resources:
            raise errors.InvalidRulesSchemaError(
                'Missing field "resource" in rule {}'.format(rule_index))

        for raw_resource in resources:
            resource_ids = raw_resource.get('resource_ids')

            if not resource_ids:
                raise errors.InvalidRulesSchemaError(
                    'Missing resource ids in rule {}'.format(rule_index))

            resource_type = raw_resource.get('type')

            if resource_type not in ['project', 'folder', 'organization']:
                raise errors.InvalidRulesSchemaError(
                    'Invalid resource type "{}" in rule {}'.format(
                        resource_type, rule_index))

            for resource_id in resource_ids:
                resource = resource_util.create_resource(
                    resource_id=resource_id,
                    resource_type=resource_type,
                )
                if not resource:
                    raise errors.InvalidRulesSchemaError(
                        'Invalid resource in rule {} (id: {}, type: {})'.format(
                            rule_index, resource_id, resource_type))

                rule = self._build_rule(rule_def, rule_index)
                self.resource_to_rules[resource].append(rule)

    @classmethod
    def _build_rule(cls, rule_def, rule_index):
        """Build a rule.

        Args:
            rule_def (dict): A dictionary containing rule definition
                properties.
            rule_index (int): The index of the rule from the rule definitions.
                Assigned automatically when the rule book is built.

        Returns:
            Rule: rule for the given definition.
        """
        for field in ['name', 'restrictions']:
            if field not in rule_def:
                raise errors.InvalidRulesSchemaError(
                    'Missing field "{}" in rule {}'.format(field, rule_index))

        return Rule(name=rule_def.get('name'),
                    index=rule_index,
                    restrictions=rule_def.get('restrictions'))

    def find_violations(self, parent_resource, liens):
        """Find lien violations in the rule book.

        Args:
            parent_resource (Resource): The GCP resource associated with the
                liens. This is where we start looking for rule violations and
                we move up the resource hierarchy (if permitted by the
                resource's "inherit_from_parents" property).
            liens (List[Lien]): The liens to look for violations.

        Yields:
            RuleViolation: lien rule violations.
        """

        all_restrictions = set()
        for lien in liens:
            for restriction in lien.restrictions:
                all_restrictions.add(restriction)

        resource_ancestors = relationship.find_ancestors(
            parent_resource, parent_resource.full_name)

        applicable_rules = []

        for res in resource_ancestors:
            applicable_rules.extend(self.resource_to_rules.get(res, []))
            wildcard_res = resource_util.create_resource(
                resource_id='*', resource_type=res.type)
            applicable_rules.extend(self.resource_to_rules.get(
                wildcard_res, []))

        for rule in applicable_rules:
            for violation in rule.find_violations(parent_resource,
                                                  all_restrictions):
                yield violation


class Rule(object):
    """Rule properties from the rule definition file.
       Also finds violations.
    """

    def __init__(self, name, index, restrictions):
        """Initialize.

        Args:
            name (str): Name of the loaded rule.
            index (int): The index of the rule from the rule definitions.
            restrictions (List[string]): The restrictions this rule enforces
              on liens.
        """
        self.name = name
        self.index = index
        self.restrictions = restrictions

    def find_violations(self, parent_resource, restrictions):
        """Find violations for this rule against the given resource.

        Args:
            parent_resource (Resource): The GCP resource associated with the
                liens.
            restrictions (Iterable[str]): The restrictions to check.

        Yields:
            RuleViolation: lien rule violation.
        """
        for restriction in self.restrictions:
            if restriction not in restrictions:
                yield RuleViolation(
                    resource_id=parent_resource.id,
                    resource_name=parent_resource.display_name,
                    resource_type=parent_resource.type,
                    full_name=parent_resource.full_name,
                    rule_index=self.index,
                    rule_name=self.name,
                    violation_type='LIEN_VIOLATION',
                    resource_data='',
                )
                return
