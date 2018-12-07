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

"""Rules engine for Big Query data sets."""
import collections
import enum
import itertools
import re

from google.cloud.forseti.common.gcp_type import resource_util
from google.cloud.forseti.common.gcp_type import resource as resource_mod
from google.cloud.forseti.common.util import logger
from google.cloud.forseti.common.util import regular_exp
from google.cloud.forseti.common.util import relationship
from google.cloud.forseti.scanner.audit import base_rules_engine as bre
from google.cloud.forseti.scanner.audit import errors as audit_errors

LOGGER = logger.get_logger(__name__)


class Mode(enum.Enum):
    """Rule modes."""
    WHITELIST = 'whitelist'
    BLACKLIST = 'blacklist'


# Rule definition wrappers.
# TODO: allow for multiple dataset ids.
RuleReference = collections.namedtuple(
    'RuleReference', ['mode', 'dataset_ids', 'bindings'])
Binding = collections.namedtuple('Binding', ['role', 'members'])
Member = collections.namedtuple(
    'Member', ['domain', 'group_email', 'user_email', 'special_group'],
)


class BigqueryRulesEngine(bre.BaseRulesEngine):
    """Rules engine for Big Query data sets"""

    def __init__(self, rules_file_path, snapshot_timestamp=None):
        """Initialize.

        Args:
            rules_file_path (str): file location of rules
            snapshot_timestamp (str): snapshot timestamp. Defaults to None.
                If set, this will be the snapshot timestamp
                used in the engine.
        """
        super(BigqueryRulesEngine,
              self).__init__(rules_file_path=rules_file_path)
        self.rule_book = None

    def build_rule_book(self, global_configs=None):
        """Build BigqueryRuleBook from the rules definition file.

        Args:
            global_configs (dict): Global configurations.
        """
        self.rule_book = BigqueryRuleBook(self._load_rule_definitions())

    def find_violations(self, parent_project, bq_acl, force_rebuild=False):
        """Determine whether Big Query datasets violate rules.

        Args:
            parent_project (Project): parent project the acl belongs to.
            bq_acl (BigqueryAccessControls): Object containing ACL data.
            force_rebuild (bool): If True, rebuilds the rule book. This will
                reload the rules definition file and add the rules to the book.

        Returns:
             generator: A generator of rule violations.
        """
        if self.rule_book is None or force_rebuild:
            self.build_rule_book()

        violations = self.rule_book.find_violations(
            parent_project, bq_acl)

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
            rule_defs (dict): rule definitons dictionary.
        """
        super(BigqueryRuleBook, self).__init__()
        self.resource_rules_map = collections.defaultdict(list)
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
        dataset_ids = []
        for dataset_id in rule_def.get('dataset_ids', []):
            dataset_ids.append(regular_exp.escape_and_globify(dataset_id))

        # Check `dataset_id` for backwards compatibility.
        # TODO: stop supporting this.
        if 'dataset_id' in rule_def:
            dataset_ids.append(
                regular_exp.escape_and_globify(rule_def['dataset_id'])
            )

        if not dataset_ids:
            raise audit_errors.InvalidRulesSchemaError(
                'Missing dataset_ids in rule {}'.format(rule_index))

        bindings = []

        # TODO: stop supporting this.
        binding = cls._get_binding_from_old_syntax(rule_def)
        if binding:
            bindings.append(binding)

        # Default mode to blacklist for backwards compatibility as that was
        # the behaviour before mode was configurable.
        # TODO: make mode required?
        mode = Mode(rule_def.get('mode', 'blacklist'))

        for raw_binding in rule_def.get('bindings', []):
            if 'role' not in raw_binding:
                raise audit_errors.InvalidRulesSchemaError(
                    'Missing role in binding in rule {}'.format(rule_index))
            role = regular_exp.escape_and_globify(raw_binding['role'])

            if 'members' not in raw_binding:
                raise audit_errors.InvalidRulesSchemaError(
                    'Missing members in binding in rule {}'.format(rule_index))

            members = []
            for raw_member in raw_binding['members']:
                fields = {
                    field: regular_exp.escape_and_globify(raw_member.get(field))
                    for field in [
                        'domain', 'group_email', 'user_email', 'special_group'
                    ]
                }

                # only one key should be set per member
                num_fields_set = sum(
                    [val is not None for val in fields.values()]
                )
                if num_fields_set != 1:
                    raise audit_errors.InvalidRulesSchemaError(
                        'At most one member field may be set in rule {}'.format(
                            rule_index))
                members.append(Member(**fields))

            bindings.append(Binding(role, members))

        if not bindings:
            raise audit_errors.InvalidRulesSchemaError(
                'Missing bindings in rule {}'.format(rule_index))

        return Rule(rule_name=rule_def.get('name'),
                    rule_index=rule_index,
                    rule_reference=RuleReference(
                        dataset_ids=dataset_ids,
                        bindings=bindings,
                        mode=mode))

    @classmethod
    def _get_binding_from_old_syntax(cls, rule_def):
        """Get a binding for configs set with the old syntax.

        Default fields to glob as default as that is what the fields used to be
        set.

        Args:
          rule_def (dict): raw rule definition.

        Returns:
          Binding: If an old style config field is set, returns a single binding
            with a single member.
        """
        keys = ['role', 'domain', 'group_email', 'user_email', 'special_group']
        for key in keys:
            if key in rule_def:
                return Binding(
                    role=regular_exp.escape_and_globify(
                        rule_def.get('role', '*')),
                    members=[Member(
                        regular_exp.escape_and_globify(
                            rule_def.get('domain', '*')),
                        regular_exp.escape_and_globify(
                            rule_def.get('group_email', '*')),
                        regular_exp.escape_and_globify(
                            rule_def.get('user_email', '*')),
                        regular_exp.escape_and_globify(
                            rule_def.get('special_group', '*')),
                    )]
                )
        return None

    def add_rule(self, rule_def, rule_index):
        """Add a rule to the rule book.

        Args:
            rule_def (dict): A dictionary containing rule definition
                properties.
            rule_index (int): The index of the rule from the rule definitions.
                Assigned automatically when the rule book is built.
        """
        resources = rule_def.get('resource')

        for raw_resource in resources:
            resource_ids = raw_resource.get('resource_ids')

            if not resource_ids or len(resource_ids) < 1:
                raise audit_errors.InvalidRulesSchemaError(
                    'Missing resource ids in rule {}'.format(rule_index))

            rule = self._build_rule(rule_def, rule_index)

            resource_type = raw_resource.get('type')
            for resource_id in resource_ids:
                resource = resource_util.create_resource(
                    resource_id=resource_id,
                    resource_type=resource_type,
                )
                self.resource_rules_map[resource].append(rule)

    def find_violations(self, resource, bq_acl):
        """Find acl violations in the rule book.

        Args:
            resource (gcp_type): The GCP resource associated with the acl.
                This is where we start looking for rule violations and
                we move up the resource hierarchy (if permitted by the
                resource's "inherit_from_parents" property).
            bq_acl (BigqueryAccessControls): The acl to compare the rules
                against.

        Returns:
            iterable: A generator of the rule violations.
        """
        violations = itertools.chain()

        resource_ancestors = (
            relationship.find_ancestors(resource, resource.full_name))

        for res in resource_ancestors:
            for rule in self.resource_rules_map.get(res, []):
                violations = itertools.chain(
                    violations, rule.find_violations(bq_acl))

        return violations


class Rule(object):
    """Rule properties from the rule definition file.
       Also finds violations.
    """

    rule_violation_attributes = ['resource_type', 'resource_id',
                                 'resource_name', 'full_name', 'rule_name',
                                 'rule_index', 'violation_type', 'dataset_id',
                                 'role', 'special_group', 'user_email',
                                 'domain', 'group_email', 'view',
                                 'resource_data']
    frozen_rule_attributes = frozenset(rule_violation_attributes)
    RuleViolation = collections.namedtuple(
        'RuleViolation',
        frozen_rule_attributes)

    def __init__(self, rule_name, rule_index, rule_reference):
        """Initialize.

        Args:
            rule_name (str): Name of the loaded rule.
            rule_index (int): The index of the rule from the rule definitions.
            rule_reference (RuleReference): The rules from the file and
              corresponding values.
        """
        self.rule_name = rule_name
        self.rule_index = rule_index
        self.rule_reference = rule_reference

    def find_violations(self, bigquery_acl):
        """Find BigQuery acl violations in the rule book.

        Args:
            bigquery_acl (BigqueryAccessControls): BigQuery ACL resource.

        Yields:
            namedtuple: Returns RuleViolation named tuple.
        """
        matches = []

        has_applicable_rules = False
        for binding in self.rule_reference.bindings:
            if not self._is_binding_applicable(binding, bigquery_acl):
                continue

            has_applicable_rules = True

            for member in binding.members:
                rule_regex_and_vals = [
                    (member.domain, bigquery_acl.domain),
                    (member.user_email, bigquery_acl.user_email),
                    (member.group_email, bigquery_acl.group_email),
                    (member.special_group, bigquery_acl.special_group),
                ]

                # Note: bindings should only have 1 member field set, so at most
                # one of the regex value pairs should be non-None. However,
                # old style configs had to set all fields, so for backwards
                # compatibility we have to check all.
                # TODO: Once we are no longer  supporting backwards
                # compatibility, just match the first non-None pair and break.
                sub_matches = [
                    re.match(regex, val)
                    for regex, val in rule_regex_and_vals
                    if regex is not None and val is not None
                ]

                if not sub_matches:
                    continue

                matches.append(all(sub_matches))

        has_violation = (
            self.rule_reference.mode == Mode.BLACKLIST and any(matches) or
            self.rule_reference.mode == Mode.WHITELIST and not any(matches)
        )

        if has_applicable_rules and has_violation:
            yield self.RuleViolation(
                resource_name=bigquery_acl.dataset_id,
                resource_type=resource_mod.ResourceType.DATASET,
                resource_id=bigquery_acl.dataset_id,
                full_name=bigquery_acl.full_name,
                rule_name=self.rule_name,
                rule_index=self.rule_index,
                violation_type='BIGQUERY_VIOLATION',
                dataset_id=bigquery_acl.dataset_id,
                role=bigquery_acl.role,
                special_group=bigquery_acl.special_group or '',
                user_email=bigquery_acl.user_email or '',
                domain=bigquery_acl.domain or '',
                group_email=bigquery_acl.group_email or '',
                view=bigquery_acl.view,
                resource_data=bigquery_acl.json,
            )

    def _is_binding_applicable(self, binding, bigquery_acl):
        """Determine whether the binding is applicable to the acl.

         Args:
            binding (Binding): rules binding to check against.
            bigquery_acl (BigqueryAccessControls): BigQuery ACL resource.
         Returns:
            bool: True if the rules are applicable to the given acl, False
                otherwise.
        """
        # only one dataset needs to match, so union all dataset ids into one
        # regex expression
        dataset_ids_matched = re.match(
            '|'.join(self.rule_reference.dataset_ids), bigquery_acl.dataset_id,
        )
        role_matched = re.match(binding.role, bigquery_acl.role)
        return dataset_ids_matched and role_matched
