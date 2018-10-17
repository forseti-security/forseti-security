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

"""Log Sinks/Exports rules engine.

Builds the RuleBook (LogSinkRuleBook) from the rule definitions (file either
stored locally or in GCS) and compares a resource's log sinks against the
RuleBook to determine whether there are violations. Log Sinks rules can be
defined on organization, folder, billing_account and project.
"""

import collections
import itertools
import re
import threading

from google.cloud.forseti.common.gcp_type import resource_util
from google.cloud.forseti.common.util import logger
from google.cloud.forseti.common.util import relationship
from google.cloud.forseti.common.util.regular_exp import escape_and_globify
from google.cloud.forseti.scanner.audit import base_rules_engine as bre
from google.cloud.forseti.scanner.audit import errors as audit_errors
from google.cloud.forseti.services.utils import to_full_resource_name


LOGGER = logger.get_logger(__name__)

VIOLATION_TYPE = 'LOG_SINK_VIOLATION'

# Rule Modes.
_WHITELIST = 'whitelist'
_BLACKLIST = 'blacklist'
_REQUIRED = 'required'
_RULE_MODES = frozenset([_WHITELIST, _BLACKLIST, _REQUIRED])


class LogSinkRulesEngine(bre.BaseRulesEngine):
    """Rules engine for Log Sinks."""

    def __init__(self, rules_file_path, snapshot_timestamp=None):
        """Initialize.

        Args:
            rules_file_path (str): File location of rules.
            snapshot_timestamp (str): The snapshot to work with.
        """
        super(LogSinkRulesEngine, self).__init__(
            rules_file_path=rules_file_path,
            snapshot_timestamp=snapshot_timestamp)
        self.rule_book = None

    def build_rule_book(self, global_configs=None):
        """Build LogSinkRuleBook from the rules definition file.

        Args:
            global_configs (dict): Global configurations.
        """
        self.rule_book = LogSinkRuleBook(
            global_configs,
            self._load_rule_definitions(),
            snapshot_timestamp=self.snapshot_timestamp)

    def find_violations(self, resource, log_sinks, force_rebuild=False):
        """Determine whether a resources's log sink config violates rules.

        Args:
            resource (gcp_type): The resource that the log sinks belong to.
            log_sinks (list): list of LogSinks for resource.
            force_rebuild (bool): If True, rebuilds the rule book.
                This will reload the rules definition file and add the
                rules to the book.

        Returns:
            iterable: A generator of rule violations.
        """
        if self.rule_book is None or force_rebuild:
            self.build_rule_book()

        violations = self.rule_book.find_violations(resource, log_sinks)

        return set(violations)

    def add_rules(self, rules):
        """Add rules to the rule book.

        Args:
            rules (list): The list of rules to add to the book.
        """
        if self.rule_book is not None:
            self.rule_book.add_rules(rules)


def _parse_sink_rule_spec(sink_spec):
    """Validates and escapes a sink from a rule config.

    Args:
        sink_spec (dict): A sink definition from a LogSink rule definition.

    Returns:
        dict: A sink definition with fields escaped and globified, or None if
        sink_spec is invalid.
    """
    if not sink_spec:
        return None

    sink_destination = sink_spec.get('destination')
    sink_filter = sink_spec.get('filter')
    sink_include_children = sink_spec.get('include_children')
    # All fields are mandatory.
    if any(item is None for item in [
            sink_destination, sink_filter, sink_include_children]):
        return None

    # include_children will either match a boolean, or allow either.
    if sink_include_children.lower() not in ['*', 'true', 'false']:
        return None
    if sink_include_children != '*':
        sink_include_children = sink_include_children.lower() == 'true'
    return {
        'destination': escape_and_globify(sink_destination),
        'filter': escape_and_globify(sink_filter),
        'include_children': sink_include_children,
    }


class LogSinkRuleBook(bre.BaseRuleBook):
    """The RuleBook for Log Sink configs.

    Rules from the rules definition file are parsed and placed into a map, which
    associates the applies_to value and GCP resource (project, folder,
    billing_account or organization) with the rules defined for it.

    Resources are evaulated against matching rules defined with applies_to =
    "self". Project resources are also evaulated against rules for ancestor
    resources defined with applies_to = "children".
    """

    supported_resource_types = frozenset([
        'project',
        'folder',
        'billing_account',
        'organization',
    ])

    supported_rule_applies_to = frozenset([
        'self',
        'children',
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
        super(LogSinkRuleBook, self).__init__()
        self._rules_sema = threading.BoundedSemaphore(value=1)
        self.resource_rules_map = {
            applies_to: collections.defaultdict(set)
            for applies_to in self.supported_rule_applies_to}
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
        return 'LogSinkRuleBook <{}>'.format(self.resource_rules_map)

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
                mode: required
                resource:
                  - type: organization
                    applies_to: children
                    resource_ids:
                      - 11223344
                sink:
                  - destination: 'bigquery.googleapis.com/projects/my-proj/*'
                    filter: 'logName:"logs/cloudaudit.googleapis.com"'
                    include_children: '*'

        ... gets parsed into:

            {
                'name': 'a rule',
                'mode': 'required',
                'resource': [{
                    'type': 'organization',
                    'applies_to': 'children',
                    'resource_ids': ['11223344']
                }],
                'sink': {
                    'destination': 'bigquery.googleapis.com/projects/my-proj/*',
                    'filter': logName:"logs/cloudaudit.googleapis.com"',
                    'include_children': '*'
                }
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
            sink = _parse_sink_rule_spec(rule_def.get('sink'))

            if not resources or sink is None or mode not in _RULE_MODES:
                raise audit_errors.InvalidRulesSchemaError(
                    'Faulty rule {}'.format(rule_index))

            for resource in resources:
                resource_type = resource.get('type')
                applies_to = resource.get('applies_to')
                resource_ids = resource.get('resource_ids')
                if resource_type not in self.supported_resource_types:
                    raise audit_errors.InvalidRulesSchemaError(
                        'Invalid resource type in rule {}'.format(rule_index))

                if applies_to not in self.supported_rule_applies_to:
                    raise audit_errors.InvalidRulesSchemaError(
                        'Invalid applies_to type in rule {}'.format(rule_index))

                if applies_to == 'children' and resource_type in [
                        'project', 'billing_account']:
                    raise audit_errors.InvalidRulesSchemaError(
                        'Rule {} cannot apply to children of a {}'.format(
                            rule_index, resource_type))

                if not resource_ids:
                    raise audit_errors.InvalidRulesSchemaError(
                        'Missing resource ids in rule {}'.format(rule_index))

                # For each resource id associated with the rule, create a
                # mapping of applies_to => resource => rules.
                for resource_id in resource_ids:
                    gcp_resource = resource_util.create_resource(
                        resource_id=resource_id,
                        resource_type=resource_type)

                    rule_def_resource = {
                        'sink': sink,
                        'mode': mode,
                    }
                    rule = Rule(rule_name=rule_def.get('name'),
                                rule_index=rule_index,
                                rule=rule_def_resource)

                    # If no mapping exists, create it. If the rule isn't in the
                    # mapping, add it.
                    self.resource_rules_map[applies_to][gcp_resource].add(rule)

        finally:
            self._rules_sema.release()

    def find_violations(self, resource, log_sinks):
        """Find Log Sink violations in the rule book.

        Args:
            resource (gcp_type): The resource that the log sinks belong to.
            log_sinks (list): list of LogSinks for resource.

        Returns:
            iterable: A generator of the rule violations.
        """
        violations = itertools.chain()

        # Check for rules that apply to this resource directly.
        resource_rules = self.resource_rules_map['self'].get(resource, [])
        for rule in resource_rules:
            violations = itertools.chain(
                violations, rule.find_violations(resource, log_sinks))

        # If resource is a project, check for ancestor rules that apply to
        # children.
        if resource.type == 'project':
            resource_ancestors = (
                relationship.find_ancestors(resource, resource.full_name))
            for curr_resource in resource_ancestors:
                resource_rules = self.resource_rules_map['children'].get(
                    curr_resource, [])
                for rule in resource_rules:
                    violations = itertools.chain(
                        violations, rule.find_violations(resource, log_sinks))

        return violations


def _sink_matches_rule(rule_def, sink):
    """Returns true if the log sink matches the rule's sink definition.

    Args:
        rule_def (dict): sink rule definition.
        sink (LogSink): sink being matched to the rule definition.

    Returns:
        bool: True if sink matches rule definition.
    """
    if (not re.match(rule_def['destination'], sink.destination) or
            not re.match(rule_def['filter'], sink.sink_filter)):
        return False
    return (rule_def['include_children'] == '*' or
            rule_def['include_children'] == sink.include_children)


def _find_whitelist_violations(rule_def, sinks):
    """Returns log sinks that DON'T match the rule definition.

    Args:
        rule_def (dict): sink whitelist rule definition.
        sinks (list): list of LogSinks to be matched against whitelist.

    Returns:
        list: All LogSinks in `sinks` that violate the whitelist.
    """
    violating_sinks = []
    for sink in sinks:
        if not _sink_matches_rule(rule_def, sink):
            violating_sinks.append(sink)
    return violating_sinks


def _find_blacklist_violations(rule_def, sinks):
    """Returns log sinks that match the rule definition.

    Args:
        rule_def (dict): sink blacklist rule definition.
        sinks (list): list of LogSinks to be matched against blacklist.

    Returns:
        list: All LogSinks in `sinks` that violate the blacklist.
    """
    violating_sinks = []
    for sink in sinks:
        if _sink_matches_rule(rule_def, sink):
            violating_sinks.append(sink)
    return violating_sinks


def _required_sink_missing(rule_def, sinks):
    """Returns True if no sink matches the rule definition.

    Args:
        rule_def (dict): required sink rule definition.
        sinks (list): list of LogSinks to be matched against required sink.

    Returns:
        bool: True if at least one log sink matches the required sink.
    """
    for sink in sinks:
        if _sink_matches_rule(rule_def, sink):
            return False
    return True


class Rule(object):
    """Rule properties from the rule definition file. Also finds violations."""

    RuleViolation = collections.namedtuple(
        'RuleViolation',
        ['resource_type', 'resource_id', 'full_name', 'rule_name', 'rule_index',
         'violation_type', 'sink_destination', 'sink_filter',
         'sink_include_children', 'resource_data', 'resource_name'])

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

    def find_violations(self, resource, log_sinks):
        """Find Log Sink violations in the rule book.

        Args:
            resource (gcp_type): The resource that the log sinks belong to.
            log_sinks (list): list of log sinks for resource.

        Yields:
            namedtuple: Returns RuleViolation named tuple.
        """
        # Required-mode violations are violations on the parent resource,
        # other violations are on the sink resource.
        if self.rule['mode'] == _REQUIRED:
            if _required_sink_missing(self.rule['sink'], log_sinks):
                sink = self.rule['sink']
                yield self.RuleViolation(
                    resource_name=resource.id,
                    resource_type=resource.type,
                    resource_id=resource.id,
                    full_name=resource.full_name,
                    rule_name=self.rule_name,
                    rule_index=self.rule_index,
                    violation_type=VIOLATION_TYPE,
                    sink_destination=sink['destination'],
                    sink_filter=sink['filter'],
                    sink_include_children=sink['include_children'],
                    resource_data=''
                )
        else:
            if self.rule['mode'] == _WHITELIST:
                violating_sinks = _find_whitelist_violations(
                    self.rule['sink'], log_sinks)
            else:
                violating_sinks = _find_blacklist_violations(
                    self.rule['sink'], log_sinks)

            # Return a violation for each sink that violates black/whitelist.
            for sink in violating_sinks:
                yield self.RuleViolation(
                    resource_name=sink.name,
                    resource_type=sink.type,
                    resource_id=sink.id,
                    full_name=to_full_resource_name(resource.full_name,
                                                    sink.id),
                    rule_name=self.rule_name,
                    rule_index=self.rule_index,
                    violation_type=VIOLATION_TYPE,
                    sink_destination=sink.destination,
                    sink_filter=sink.sink_filter,
                    sink_include_children=sink.include_children,
                    resource_data=sink.raw_json
                )
