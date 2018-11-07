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

"""Rules engine for resource locations."""

import collections
import enum
import re

from google.cloud.forseti.common.gcp_type import resource
from google.cloud.forseti.common.gcp_type import resource_util
from google.cloud.forseti.common.util import logger
from google.cloud.forseti.common.util import regular_exp
from google.cloud.forseti.common.util import relationship
from google.cloud.forseti.scanner.audit import base_rules_engine
from google.cloud.forseti.scanner.audit import errors

LOGGER = logger.get_logger(__name__)

SUPPORTED_RULE_RESOURCE_TYPES = frozenset(['project', 'folder', 'organization'])

SUPPORTED_LOCATION_RESOURCE_TYPES = frozenset([
    resource.ResourceType.BUCKET,
    resource.ResourceType.CLOUD_SQL_INSTANCE,
    resource.ResourceType.DATASET,
    resource.ResourceType.INSTANCE,
    resource.ResourceType.KE_CLUSTER,
])

LocationData = collections.namedtuple(
    'LocationData', ['resource', 'locations']
)

RuleViolation = collections.namedtuple(
    'RuleViolation',
    ['resource_id', 'resource_name', 'resource_type', 'full_name', 'rule_index',
     'rule_name', 'violation_type', 'violation_data', 'resource_data']
)


class Mode(enum.Enum):
    """Rule modes."""
    WHITELIST = 'whitelist'
    BLACKLIST = 'blacklist'


class LocationRulesEngine(base_rules_engine.BaseRulesEngine):
    """Rules engine for resource locations."""

    def __init__(self, rules_file_path, snapshot_timestamp=None):
        """Initialize.

        Args:
            rules_file_path (str): file location of rules
            snapshot_timestamp (str): snapshot timestamp. Defaults to None.
                If set, this will be the snapshot timestamp
                used in the engine.
        """
        super(LocationRulesEngine, self).__init__(
            rules_file_path=rules_file_path)
        self.rule_book = None

    def build_rule_book(self, global_configs=None):
        """Build LocationRuleBook from the rules definition file.

        Args:
            global_configs (dict): Global configurations.
        """
        self.rule_book = LocationRuleBook(self._load_rule_definitions())

    def find_violations(self, res, force_rebuild=False):
        """Determine whether resources violate rules.

        Args:
            res (Resource): resource to check locations for.
            force_rebuild (bool): If True, rebuilds the rule book. This will
                reload the rules definition file and add the rules to the book.

        Returns:
             generator: A generator of rule violations.
        """
        if self.rule_book is None or force_rebuild:
            self.build_rule_book()

        violations = self.rule_book.find_violations(res)
        return violations

    def add_rules(self, rule_defs):
        """Add rules to the rule book.

        Args:
            rule_defs (dict): rule definitions dictionary
        """
        if self.rule_book is not None:
            self.rule_book.add_rules(rule_defs)


class LocationRuleBook(base_rules_engine.BaseRuleBook):
    """The RuleBook for resource locations."""

    def __init__(self, rule_defs=None):
        """Initialization.

        Args:
            rule_defs (dict): rule definitons dictionary.
        """
        super(LocationRuleBook, self).__init__()
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

            if resource_type not in SUPPORTED_RULE_RESOURCE_TYPES:
                raise errors.InvalidRulesSchemaError(
                    'Invalid resource type "{}" in rule {}'.format(
                        resource_type, rule_index))

            for resource_id in resource_ids:
                res = resource_util.create_resource(
                    resource_id=resource_id,
                    resource_type=resource_type,
                )
                if not res:
                    raise errors.InvalidRulesSchemaError(
                        'Invalid resource in rule {} (id: {}, type: {})'.format(
                            rule_index, resource_id, resource_type))

                rule = self._build_rule(rule_def, rule_index)
                self.resource_to_rules[res].append(rule)

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
        for field in ['name', 'mode', 'applies_to', 'locations']:
            if field not in rule_def:
                raise errors.InvalidRulesSchemaError(
                    'Missing field "{}" in rule {}'.format(field, rule_index))

        applies_to = {}

        for applies_dict in rule_def.get('applies_to'):
            # For backwards compatibility for when applies_to was a string.
            if isinstance(applies_dict, str):
                applies_dict = {'type': applies_dict, 'resource_ids': ['*']}

            resource_type = applies_dict['type']

            if resource_type != '*' and (
                    resource_type not in SUPPORTED_LOCATION_RESOURCE_TYPES):
                raise errors.InvalidRulesSchemaError(
                    'Unsupported applies to type "{}" in rule {}'.format(
                        resource_type, rule_index))

            applies_to[resource_type] = applies_dict['resource_ids']

        return Rule(name=rule_def.get('name'),
                    index=rule_index,
                    mode=Mode(rule_def.get('mode')),
                    applies_to=applies_to,
                    location_patterns=rule_def.get('locations'))

    def find_violations(self, res):
        """Find resource locations violations in the rule book.

        Args:
            res (Resource): The GCP resource to check locations for.
                This is where we start looking for rule violations and
                we move up the resource hierarchy.

        Yields:
            RuleViolation: resource locations rule violations.
        """

        resource_ancestors = relationship.find_ancestors(
            res, res.full_name)

        rules = []
        for ancestor_res in resource_ancestors:
            rules.extend(self.resource_to_rules.get(ancestor_res, []))

        type_resource_wildcard = resource_util.create_resource(
            resource_id='*', resource_type=res.type)

        rules.extend(self.resource_to_rules.get(type_resource_wildcard, []))

        for rule in rules:
            for violation in rule.find_violations(res):
                yield violation


class Rule(object):
    """Rule properties from the rule definition file.
       Also finds violations.
    """

    def __init__(self, name, index, mode, applies_to, location_patterns):
        """Initialize.

        Args:
            name (str): Name of the loaded rule.
            index (int): The index of the rule from the rule definitions.
            mode (Mode): The mode of this rule.
            applies_to (List[str]): list of resource types that the rule applies
                to.
            location_patterns (List[str]): Forseti-style patterns for locations.
        """
        self.name = name
        self.index = index
        self.mode = mode
        self.applies_to = applies_to

        loc_re_str = '|'.join([
            regular_exp.escape_and_globify(loc_wildcard.lower(),
                                           wildcard_is_zero_or_more=True)
            for loc_wildcard in location_patterns
        ])
        self.location_re = re.compile(loc_re_str)

    def find_violations(self, res):
        """Find violations for this rule against the given resource.

        Args:
            res (Resource): The resource to check for violations.

        Yields:
            RuleViolation: location rule violation.
        """
        applicable_resources = self.applies_to.get(res.type, [])
        applicable_resources.extend(self.applies_to.get('*', []))
        applicable_resources = set(applicable_resources)

        if applicable_resources != {'*'} and (
                res.id not in applicable_resources):
            return

        matches = [
            self.location_re.match(loc.lower()) for loc in res.locations
        ]

        has_violation = (
            self.mode == Mode.BLACKLIST and any(matches) or
            self.mode == Mode.WHITELIST and not any(matches)
        )

        if has_violation:
            yield RuleViolation(
                resource_id=res.id,
                resource_name=res.display_name,
                resource_type=res.type,
                full_name=res.full_name,
                rule_index=self.index,
                rule_name=self.name,
                violation_type='LOCATION_VIOLATION',
                violation_data=str(res.locations),
                resource_data=res.data,
            )
            return
