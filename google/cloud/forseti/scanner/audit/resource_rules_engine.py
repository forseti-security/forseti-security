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

from google.cloud.forseti.common.util import logger
from google.cloud.forseti.scanner.audit import base_rules_engine
from google.cloud.forseti.scanner.audit import errors
from google.cloud.forseti.services import utils

LOGGER = logger.get_logger(__name__)

_SUPPORTED_MODES = {'required'}

RuleViolation = collections.namedtuple(
    'RuleViolation',
    ['resource_id', 'resource_name', 'resource_type', 'full_name', 'rule_index',
     'rule_name', 'violation_type', 'violation_data', 'resource_data']
)


class ResourceRulesEngine(base_rules_engine.BaseRulesEngine):
    """Rules engine for Resources."""

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
        """Build ResourceRuleBook from the rules definition file.

        Args:
            global_configs (dict): Global configurations.
        """
        self.rule_book = ResourceRuleBook(self._load_rule_definitions())

    def find_violations(self, resources, force_rebuild=False):
        """Determine whether the resources violate rules.

        Args:
            resources (List[Resource]): resources to find violations for.
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
    """The RuleBook for Resources."""

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

        raises:
            InvalidRulesSchemaError: if invalid rules definition.
        """
        mode = rule_def.get('mode', '')
        if mode not in _SUPPORTED_MODES:
            raise errors.InvalidRulesSchemaError(
                'Unexpected "mode" in rule {}: got {}, want one of {}'.format(
                    rule_index, mode, _SUPPORTED_MODES))
        if not rule_def.get('resource_types'):
            raise errors.InvalidRulesSchemaError(
                'Missing non empty "resource_types" in rule {}'.format(
                    rule_index))

        resource_tree = ResourceTree.from_json(
            rule_def.get('resource_trees', []))
        self.rules.append(
            Rule(name=rule_def['name'],
                 index=rule_index,
                 resource_types=set(rule_def['resource_types']),
                 resource_tree=resource_tree))

    def find_violations(self, resources):
        """Find resource violations in the rule book.

        Args:
            resources (List[Resource]): The resources to check for violations.

        Yields:
            RuleViolation: resource rule violations.
        """
        for rule in self.rules:
            for violation in rule.find_violations(resources):
                yield violation

    def get_applicable_resource_types(self):
        """Get the applicable resource types defined in this rule book.

        The applcable resource types are a union of all resource types defined
        in each rule.

        Returns:
            Set[string]: applicable resource types.
        """
        types = set()
        for rule in self.rules:
            types.update(rule.resource_types)
        return types


class ResourceTree(object):
    """ResourceTree represents resources in a tree format."""

    def __init__(self, resource_type=None, resource_id=None, children=None):
        """Initialize a resource tree.

        Args:
            resource_type (str): type of this resource. Leave as None if
              this is a root node with multiple children. In that case,
              this tree will represent a multi-root tree.
            resource_id (str): id of this resource or '*'. Leave as None if
              this is a root node with multiple children. In that case,
              this tree will represent a multi-root tree.
            children (List[ResourceTree]): children of this node.
        """
        self.resource_type = resource_type
        self.resource_id = resource_id
        self.children = children or []

    @classmethod
    def from_json(cls, json_nodes):
        """Create a resource tree from the given JSON representation of nodes.

        If there are multiple json nodes, the resulting tree will have a root
        node with no resource type or id and each json node as a child.

        If there is only one json node, the root will have the resource id and
        type of the node.

        Args:
            json_nodes(List[dict]): JSON representation of nodes.

        Returns:
            ResourceTree: The resource tree representation of the json nodes.
        """
        nodes = cls._from_json(json_nodes)
        if len(nodes) == 1:
            return nodes[0]
        return ResourceTree(children=nodes)

    @classmethod
    def _from_json(cls, json_nodes):
        """Build Resource Tree nodes.

        Args:
            json_nodes(List[dict]): JSON representation of nodes.

        Returns:
            ResourceTree: The resource tree representation of the json nodes.
        """
        nodes = []
        for json_node in json_nodes:
            node = ResourceTree(
                resource_type=json_node['type'],
                resource_id=json_node['resource_id'],
                children=cls._from_json(json_node.get('children', [])))
            nodes.append(node)
        return nodes

    def match(self, resource, resource_types):
        """Match the given resource against this resource tree.

        Args:
            resource (Resource): The resource to match.
            resource_types (List[string]): Applicable resource types. Violations
                on types not in this list will not be reported.

        Returns:
            ResourceTree: The final matching node, or None if there is no match.
        """
        tuples = []
        for resource_type, resource_id in (
                utils.get_resources_from_full_name(resource.full_name)):
            tuples.append((resource_type, resource_id))

        # Tuples are returned in reverse order, so reverse them.
        tuples = list(reversed(tuples))

        # Left trim tuples that are not appicable.
        for resource_type, _ in tuples:
            if resource_type not in resource_types:
                tuples = tuples[1:]

        if not tuples:
            return None

        return self.match_tuples(tuples)

    def match_tuples(self, tuples):
        """Match the given tuples against this tree.

        Args:
           tuples (List[Tuple[string, string]]): (type, id) pairs of resources.
              Together, they represent one full resource.
              e.g. organization/123/project/456/ should be represented as
              [('organization', '123'), ('project', '456')].

        Returns:
            ResourceTree: The final matching node, or None if there is no match.
        """
        if not self.resource_type:
            return self._find_matching_child(tuples)

        for resource_type, resource_id in tuples:
            id_match = self.resource_id == '*' or (
                resource_id == self.resource_id)

            if resource_type == self.resource_type and id_match:
                tuples = tuples[1:]
                if not tuples:
                    return self
                if not self.children:
                    return None
                return self._find_matching_child(tuples)
        return None

    def _find_matching_child(self, tuples):
        """Finds a matching child node.

        Assumes that a child will either match an exact resource id, or a
        wildcard. The exact match child is given preference.

        Args:
            tuples (List[Tuple[string, string]]): (type, id) pairs of resources.
              Together, they represent one full resource.
              e.g. organization/123/project/456/ should be represented as
              [('organization', '123'), ('project', '456')].

        Returns:
            ResourceTree: Matching child node, or None if none matched.
        """
        wildcard_child = None
        for child in self.children:
            node = child.match_tuples(tuples)
            if node:
                if node.resource_id != '*':
                    return node
                else:
                    wildcard_child = node
        return wildcard_child

    def get_nodes(self):
        """Get all nodes in this resource tree.

        Returns:
            List[ResourceTree]: nodes in this tree.
        """
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

    def __init__(self, name, index, resource_types, resource_tree):
        """Initialize.

        Args:
            name (str): Name of the loaded rule.
            index (int): The index of the rule from the rule definitions.
            resource_types (List[str]): The applicable resource types of this
                rule.
            resource_tree (ResourceTree): Tree representing the valid resources.
        """
        self.name = name
        self.index = index
        self.resource_types = resource_types
        self.resource_tree = resource_tree

    def find_violations(self, resources):
        """Find violations for this rule against the given resource.

        Args:
            resources (List[Resource]): resources to check for violations.

        Yields:
            RuleViolation: resource rule violation.
        """

        matched_nodes = set()
        for resource in resources:
            if resource.type not in self.resource_types:
                continue
            node = self.resource_tree.match(resource, self.resource_types)
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
                    violation_data='',
                    resource_data=resource.data or '',
                )

        for node in self.resource_tree.get_nodes():
            if node.resource_id != '*' and (
                    node not in matched_nodes):
                yield RuleViolation(
                    resource_id=node.resource_id,
                    resource_name=node.resource_id,
                    resource_type=node.resource_type,
                    full_name=node.resource_id,
                    rule_index=self.index,
                    rule_name=self.name,
                    violation_type='RESOURCE_VIOLATION',
                    violation_data='',
                    resource_data='',
                )
