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

"""Rules engine for Resources."""
import collections

from google.cloud.forseti.common.gcp_type import resource_util
from google.cloud.forseti.common.util import logger
from google.cloud.forseti.common.util import relationship
from google.cloud.forseti.scanner.audit import base_rules_engine
from google.cloud.forseti.scanner.audit import errors
from google.cloud.forseti.services import utils

LOGGER = logger.get_logger(__name__)


RuleViolation = collections.namedtuple(
    'RuleViolation',
    ['resource_id', 'resource_name', 'resource_type', 'full_name', 'rule_index',
     'rule_name', 'violation_type', 'resource_data']
)


class ResourceRulesEngine(base_rules_engine.BaseRulesEngine):
    """Rules engine for Liens."""

    def __init__(self, rules_file_path, snapshot_timestamp=None):
        """Initialize.

        Args:
            rules_file_path (str): file location of rules
            snapshot_timestamp (str): snapshot timestamp. Defaults to None.
                If set, this will be the snapshot timestamp
                used in the engine.
        """
        super(ResourceRulesEngine, self).__init__(
            rules_file_path=rules_file_path)
        self.rule_book = None

    def build_rule_book(self, global_configs=None):
        """Build LienRuleBook from the rules definition file.

        Args:
            global_configs (dict): Global configurations.
        """
        self.rule_book = ResourceRuleBook(self._load_rule_definitions())

    def find_violations(self, resources, force_rebuild=False):
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

        violations = self.rule_book.find_violations(resources)
        return violations

    def add_rules(self, rule_defs):
        """Add rules to the rule book.

        Args:
            rule_defs (dict): rule definitions dictionary
        """
        if self.rule_book is not None:
            self.rule_book.add_rules(rule_defs)


class ResourceRuleBook(base_rules_engine.BaseRuleBook):
    """The RuleBook for Lien resources."""

    def __init__(self, rule_defs=None):
        """Initialization.

        Args:
            rule_defs (dict): rule definitons dictionary.
        """
        super(ResourceRuleBook, self).__init__()
        self.rules = []
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
        resource_tree = ResourceTree.from_json(rule_def['resource_trees'])
        self.rules.append(
            Rule(name=rule_def['name'],
            index=rule_index,
            resource_tree=resource_tree),
        )

    def find_violations(self, resources):
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
        for rule in self.rules:
            for violation in rule.find_violations(resources):
                yield violation


class ResourceTree(object):

    def __init__(self, resource_type=None, resource_id=None, children=None):
        self.resource_type = resource_type
        self.resource_id = resource_id
        self.children = children or []

    @classmethod
    def from_json(cls, json_nodes):
        nodes = cls._from_json(json_nodes)
        if not nodes:
            return None
        elif len(nodes) == 1:
            return nodes[0]
        else:
            return ResourceTree(children=nodes)

    @classmethod
    def _from_json(cls, json_nodes):
        if not json_nodes:
            return None
        nodes = []
        for json_node in json_nodes:
            node = ResourceTree(
                resource_type=json_node['type'],
                resource_id=json_node['resource_id'],
                children=cls._from_json(json_node.get('children')))
            nodes.append(node)
        return nodes

    def match(self, resource):
        tuples = []
        for resource_type, resource_id  in (
            utils.get_resources_from_full_name(resource.full_name)):
            tuples.append((resource_type, resource_id))

        if not tuples:
            return None

        if self.resource_type:
            root_resource_types = {self.resource_type}
        else:
            root_resource_types = {
                child.resource_type for child in self.children}

        tuples = list(reversed(tuples))

        for resource_type, _ in tuples:
            if resource_type in root_resource_types:
                break
            tuples = tuples[1:]

        return self._match(tuples)

    def _match(self, tuples):
        if not self.resource_type:
            for child in self.children:
                node = child._match(tuples)
                if node:
                    return node

        for resource_type, resource_id in tuples:
            if resource_type == self.resource_type and (
                resource_id == self.resource_id):
                    tuples = tuples[1:]
                    if not tuples:
                        return self
                    elif not self.children:
                        return None
                    else:
                        for child in self.children:
                            node = child._match(tuples)
                            if node:
                                return node

    def get_nodes(self):
        nodes = []
        if self.resource_type:
            nodes.append(self)
        for child in self.children:
            nodes.extend(child.get_nodes())
        return nodes



class Rule(object):
    """Rule properties from the rule definition file.
       Also finds violations.
    """

    def __init__(self, name, index, resource_tree):
        """Initialize.

        Args:
            name (str): Name of the loaded rule.
            index (int): The index of the rule from the rule definitions.
            restrictions (List[string]): The restrictions this rule enforces
              on liens.
        """
        self.name = name
        self.index = index
        self.resource_tree = resource_tree

    def find_violations(self, resources):
        """Find violations for this rule against the given resource.

        Args:
            parent_resource (Resource): The GCP resource associated with the
                liens.
            restrictions (Iterable[str]): The restrictions to check.

        Yields:
            RuleViolation: lien rule violation.
        """

        matched_nodes = set()
        for resource in resources:
            node = self.resource_tree.match(resource)
            if node:
                matched_nodes.add(node)
            else:
                yield RuleViolation(
                    resource_id=resource.id,
                    resource_name=resource.display_name,
                    resource_type=resource.type,
                    full_name=resource.full_name,
                    rule_index=self.index,
                    rule_name=self.name,
                    violation_type='RESOURCE_VIOLATION',
                    resource_data=resource.data or '',
                )

        for node in self.resource_tree.get_nodes():
            if node not in matched_nodes:
                yield RuleViolation(
                    resource_id=node.resource_id,
                    resource_name=node.resource_id,
                    resource_type=node.resource_type,
                    full_name=node.resource_id,
                    rule_index=self.index,
                    rule_name=self.name,
                    violation_type='RESOURCE_VIOLATION',
                    resource_data='')
