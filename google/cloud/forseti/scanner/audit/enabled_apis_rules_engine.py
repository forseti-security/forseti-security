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

"""Enabled APIS rules engine for organizations, folders, and projects.

Builds the RuleBook (EnabledApisRuleBook) from the rule definitions (file either
stored locally or in GCS) and compares a list of APIs  against the RuleBook to
determine whether there are violations.
"""

import collections
import itertools
import threading

from google.cloud.forseti.common.gcp_type import resource_util
from google.cloud.forseti.common.util import logger
from google.cloud.forseti.common.util import relationship
from google.cloud.forseti.scanner.audit import base_rules_engine as bre
from google.cloud.forseti.scanner.audit import errors as audit_errors

LOGGER = logger.get_logger(__name__)

# Rule violation type.
VIOLATION_TYPE = 'ENABLED_APIS_VIOLATION'

# Rule Modes.
_WHITELIST = 'whitelist'
_BLACKLIST = 'blacklist'
_REQUIRED = 'required'
_RULE_MODES = frozenset([_WHITELIST, _BLACKLIST, _REQUIRED])


def _check_whitelist_apis(rule_apis=None, enabled_apis=None):
    """Whitelist: Checks that enabled APIs ARE in rule APIs.

    If an enabled api is NOT found in the rule APIs, add it to
    the violating APIs.

    Args:
        rule_apis (list): ManagedService APIs allowed in the rule.
        enabled_apis (list): ManagedService APIs enabled by the project.

    Returns:
        list: Enabled APIs NOT found in the whitelist (rule APIs).
    """
    violating_apis = []
    for api in enabled_apis:
        if api not in rule_apis:
            violating_apis.append(api)
    return violating_apis


def _check_blacklist_apis(rule_apis=None, enabled_apis=None):
    """Blacklist: Checks that enabled APIs ARE NOT in rule APIs.

    If an enabled API is found in the rule APIs, add it to the
    violating APIs.

    Args:
        rule_apis (list): ManagedService APIs dis-allowed in the rule.
        enabled_apis (list): ManagedService APIs enabled by the project.

    Returns:
        list: Enabled APIs found in the blacklist (rule APIs).
    """
    violating_apis = []
    for api in enabled_apis:
        if api in rule_apis:
            violating_apis.append(api)
    return violating_apis


def _check_required_apis(rule_apis=None, enabled_apis=None):
    """Required: Checks that rule APIs are in enabled APIs.

    If a required rule API is NOT found enabled in the project, add it to the
    violating APIs.

    Args:
        rule_apis (list): ManagedService APIs required in the rule.
        enabled_apis (list): ManagedService APIs enabled by the project.

    Returns:
        list: Required rule APIs not found enabled by the project.
    """
    violating_apis = []
    for api in rule_apis:
        if api not in enabled_apis:
            violating_apis.append(api)
    return violating_apis


class EnabledApisRulesEngine(bre.BaseRulesEngine):
    """Rules engine for enabled APIs."""

    def __init__(self, rules_file_path, snapshot_timestamp=None):
        """Initialize.

        Args:
            rules_file_path (str): File location of rules.
            snapshot_timestamp (str): The snapshot to work with.
        """
        super(EnabledApisRulesEngine, self).__init__(
            rules_file_path=rules_file_path,
            snapshot_timestamp=snapshot_timestamp)
        self.rule_book = None

    def build_rule_book(self, global_configs=None):
        """Build EnabledApisRuleBook from the rules definition file.

        Args:
            global_configs (dict): Global configurations.
        """
        self.rule_book = EnabledApisRuleBook(
            global_configs,
            self._load_rule_definitions(),
            snapshot_timestamp=self.snapshot_timestamp)

    def find_violations(self, project, enabled_apis, force_rebuild=False):
        """Determine whether enabled APIs violates rules.

        Args:
            project (gcp_type): The project that these APIs are enabled on.
            enabled_apis (list): list of enabled APIs.
            force_rebuild (bool): If True, rebuilds the rule book.
                This will reload the rules definition file and add the
                rules to the book.

        Returns:
            iterable: A generator of rule violations.
        """
        if self.rule_book is None or force_rebuild:
            self.build_rule_book()

        violations = self.rule_book.find_violations(project, enabled_apis)

        return set(violations)

    def add_rules(self, rules):
        """Add rules to the rule book.

        Args:
            rules (list): The list of rules to add to the book.
        """
        if self.rule_book is not None:
            self.rule_book.add_rules(rules)


class EnabledApisRuleBook(bre.BaseRuleBook):
    """The RuleBook for Enabled APIs resources.

    Rules from the rules definition file are parsed and placed into a map, which
    associates the GCP resource (project, folder or organization) with the
    rules defined for it.

    A project's enabled APIs are evaulated against rules for all ancestor
    resources of that project.
    """

    supported_resource_types = frozenset([
        'project',
        'folder',
        'organization',
    ])

    def __init__(self,
                 global_configs,  # pylint: disable= unused-argument
                 rule_defs=None,
                 snapshot_timestamp=None):
        """Initialize.

        Args:
            global_configs (dict): Global configurations.
            rule_defs (dict): The parsed dictionary of rules from the YAML
                definition file.
            snapshot_timestamp (str): The snapshot to lookup data.
        """
        super(EnabledApisRuleBook, self).__init__()
        self._rules_sema = threading.BoundedSemaphore(value=1)
        self.resource_rules_map = collections.defaultdict(set)
        if not rule_defs:
            self.rule_defs = {}
        else:
            self.rule_defs = rule_defs
            self.add_rules(rule_defs)
        if snapshot_timestamp:
            self.snapshot_timestamp = snapshot_timestamp

    def __eq__(self, other):
        """Equals.

        Args:
            other (object): Object to compare.

        Returns:
            bool: True or False.
        """
        if not isinstance(other, type(self)):
            return NotImplemented
        return self.resource_rules_map == other.resource_rules_map

    def __ne__(self, other):
        """Not Equals.

        Args:
            other (object): Object to compare.

        Returns:
            bool: True or False.
        """
        return not self == other

    def __repr__(self):
        """Object representation.

        Returns:
            str: The object representation.
        """
        return 'EnabledApisRuleBook <{}>'.format(self.resource_rules_map)

    def add_rules(self, rule_defs):
        """Add rules to the rule book.

        Args:
            rule_defs (dict): Rules parsed from the rule definition file.
        """
        for (i, rule) in enumerate(rule_defs.get('rules', [])):
            self.add_rule(rule, i)

    def add_rule(self, rule_def, rule_index):
        """Add a rule to the rule book.

        The rule supplied to this method is the dictionary parsed from
        the rules definition file.

        For example, this rule...

            # rules yaml:
            rules:
              - name: a rule
                mode: whitelist
                resource:
                  - type: project
                    resource_ids:
                      - my-project-123
                services:
                  - 'compute.googleapis.com'
                  - 'storage-component.googleapis.com'
                  - 'storage-api.googleapis.com'

        ... gets parsed into:

            {
                'name': 'a rule',
                'mode': 'whitelist',
                'resource': {
                    'type': 'project',
                    'resource_ids': ['my-project-id']
                },
                'services': [
                    'compute.googleapis.com',
                    'storage-component.googleapis.com',
                    'storage-api.googleapis.com'
                ]
            }

        Args:
            rule_def (dict): Contains rule definition properties.
            rule_index (int): The index of the rule from the rule definitions.
                Assigned automatically when the rule book is built.
        """
        self._rules_sema.acquire()

        try:
            resources = rule_def.get('resource')
            mode = rule_def.get('mode')
            services = rule_def.get('services')
            if not resources or not services or mode not in _RULE_MODES:
                raise audit_errors.InvalidRulesSchemaError(
                    'Faulty rule {}'.format(rule_index))

            for resource in resources:
                resource_ids = resource.get('resource_ids')
                resource_type = resource.get('type')
                if resource_type not in self.supported_resource_types:
                    raise audit_errors.InvalidRulesSchemaError(
                        'Invalid resource type in rule {}'.format(rule_index))

                if not resource_ids or len(resource_ids) < 1:
                    raise audit_errors.InvalidRulesSchemaError(
                        'Missing resource ids in rule {}'.format(rule_index))

                # For each resource id associated with the rule, create a
                # mapping of resource => rules.
                for resource_id in resource_ids:
                    if resource_id == '*' and resource_type != 'project':
                        raise audit_errors.InvalidRulesSchemaError(
                            'Wild-card must use project type in rule {}'.format(
                                rule_index))
                    gcp_resource = resource_util.create_resource(
                        resource_id=resource_id,
                        resource_type=resource_type)

                    rule_def_resource = {
                        'services': services,
                        'mode': mode,
                    }
                    rule = Rule(rule_name=rule_def.get('name'),
                                rule_index=rule_index,
                                rule=rule_def_resource)

                    # If no mapping exists, create it. If the rule isn't in the
                    # mapping, add it.
                    self.resource_rules_map[gcp_resource].add(rule)

        finally:
            self._rules_sema.release()

    def find_violations(self, project, enabled_apis):
        """Find enabled APIs violations in the rule book.

        Args:
            project (gcp_type): The project that these APIs are enabled on.
            enabled_apis (list): list of enabled APIs.

        Returns:
            iterable: A generator of the rule violations.
        """
        violations = itertools.chain()

        # Check for rules on all ancestors, and the wildcard rule.
        resource_ancestors = (
            relationship.find_ancestors(project, project.full_name))
        resource_ancestors.append(resource_util.create_resource(
            resource_id='*', resource_type='project'))

        for curr_resource in resource_ancestors:
            resource_rules = self.resource_rules_map.get(curr_resource, [])
            for resource_rule in resource_rules:
                violations = itertools.chain(
                    violations,
                    resource_rule.find_violations(project, enabled_apis))

        return violations


# Mapping from rule mode to mode check method.
_RULE_MODE_METHODS = {
    _WHITELIST: _check_whitelist_apis,
    _BLACKLIST: _check_blacklist_apis,
    _REQUIRED: _check_required_apis,
}


class Rule(object):
    """Rule properties from the rule definition file. Also finds violations."""

    RuleViolation = collections.namedtuple(
        'RuleViolation',
        ['resource_type', 'resource_id', 'full_name', 'rule_name', 'rule_index',
         'violation_type', 'apis', 'resource_data', 'resource_name'])

    def __init__(self, rule_name, rule_index, rule):
        """Initialize.
        Args:
            rule_name (str): Name of the loaded rule.
            rule_index (int): The index of the rule from the rule definitions.
            rule (dict): The rule definition from the file.
        """
        self.rule_name = rule_name
        self.rule_index = rule_index
        self.rule = rule

    def find_violations(self, project, enabled_apis):
        """Find Enabled API violations in the rule book.
        Args:
            project (gcp_type): The project that these APIs are enabled on.
            enabled_apis (list): list of enabled APIs.
        Yields:
            namedtuple: Returns RuleViolation named tuple.
        """

        violating_apis = _RULE_MODE_METHODS[self.rule['mode']](
            rule_apis=self.rule['services'],
            enabled_apis=enabled_apis)

        if violating_apis:
            yield self.RuleViolation(
                resource_name=project.display_name,
                resource_type=project.type,
                resource_id=project.id,
                full_name=project.full_name,
                rule_name=self.rule_name,
                rule_index=self.rule_index,
                violation_type=VIOLATION_TYPE,
                apis=tuple(violating_apis),
                resource_data=project.data
            )
