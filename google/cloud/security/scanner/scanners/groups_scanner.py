# Copyright 2017 Google Inc.
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

"""Scanner for Google Groups."""

from Queue import Queue

import anytree
import yaml

from google.cloud.security.common.util import log_util
from google.cloud.security.common.data_access import group_dao
from google.cloud.security.scanner.scanners import base_scanner
from google.cloud.security.scanner.audit import rules


# TODO: The next editor must remove this disable and correct issues.
# pylint: disable=missing-type-doc,missing-return-type-doc
# pylint: disable=missing-param-doc,differing-param-doc
# pylint: disable=redundant-returns-doc


LOGGER = log_util.get_logger(__name__)
MY_CUSTOMER = 'my_customer'


class GroupsScanner(base_scanner.BaseScanner):
    """Pipeline to IAM data from DAO"""

    def __init__(self, global_configs, scanner_configs, snapshot_timestamp,
                 rules):
        """Constructor for the base pipeline.

        Args:
            global_configs (dict): Global configurations.
            snapshot_timestamp: String of timestamp, formatted as
                YYYYMMDDTHHMMSSZ.

        Returns:
            None
        """
        super(GroupsScanner, self).__init__(
            global_configs,
            scanner_configs,
            snapshot_timestamp,
            rules)
        self.dao = group_dao.GroupDao(global_configs)


    def _flatten_violations(self, violations):
        for violation in violations:
            violation_data = {}
            violation_data['violated_rule_names'] = violation.violated_rule_names
            violation_data['member_email'] = violation.member_email
            violation_data['member_id'] = violation.member_id
            violation_data['member_status'] = violation.member_status
            violation_data['member_type'] = violation.member_type
            violation_data['parent_email'] = violation.parent.member_email
            violation_data['parent_id'] = violation.parent.member_id
            violation_data['parent_status'] = violation.parent.member_status
            violation_data['parent_type'] = violation.parent.member_type
            yield {
                'resource_id': violation.member_email,
                'resource_type': 'group_member',
                'rule_index': None,
                'rule_name': violation.violated_rule_names,
                'violation_type': rules.VIOLATION_TYPE.get('whitelist'),
                'violation_data': violation_data
            }

    def _output_results(self, all_violations):
        resource_name = 'violations'

        all_violations = self._flatten_violations(all_violations)
        self._output_results_to_db(resource_name, all_violations)


    # pylint: disable=arguments-differ
    # pylint: disable=too-many-branches
    def find_violations(self, root):
        """Find violations, starting from the given root.

        At this point, we can start to find violations at each node!

        We have a tree, with data populated at each node.
        ...and rules are also applied at each node.
        Traversal order should not matter, since we need to evaluate all nodes.

        Each node can have multiple rules.
        Each rule can have multiple conditions.

        If a rule is violated, then the node is in violation.
        i.e. if all rules pass, then the node is not in violation.

        Args:
            root: The nodes (tree structure) to find violations in.

        Returns:
            A list of nodes that are in violation.
        """
        all_violations = []
        for node in anytree.iterators.PreOrderIter(root):

            # No need to evaluate these nodes.
            # This represents the org, i.e. is not a group.
            if node.member_email == MY_CUSTOMER:
                continue
            # This represents the auto-generated group, containing all the users
            # in the org.
            if not node.member_email:
                continue

            node.violated_rule_names = []
            whitelist_rule_statuses = []
            for rule in node.rules:
                condition_statuses = []

                if rule.get('mode') == 'whitelist':
                    for condition in rule.get('conditions'):
                        if condition.get('member_email') in node.member_email:
                            condition_statuses.append(True)
                        else:
                            condition_statuses.append(False)

                    # All the conditions of this rule have evaluated.
                    # The rule is fulfilled, if any condition matches.
                    if any(condition_statuses):
                        whitelist_rule_statuses.append(True)
                    else:
                        whitelist_rule_statuses.append(False)
                        node.violated_rule_names.append(rule.get('name'))

                elif rule.get('mode') == 'blacklist':
                    pass  # TODO

                elif rule.get('mode') == 'required':
                    pass  # TODO

                else:
                    pass  # TODO

            # Determine if the node is in violations or not.
            # All rules must be fulfilled, for a node to not be in violation.
            # If any rule is not fulfilled, then node is in violation.
            #
            # truth table
            # http://stackoverflow.com/a/19389957/2830207
            if not any(whitelist_rule_statuses):
                all_violations.append(node)

        return all_violations

    @staticmethod
    def _apply_one_rule(starting_node, rule):
        """Append the rule to all the applicable nodes.

        Args:
            starting_node: Member node from which to start appending the rule.
            rule: A dictionary representation of a rule.

        Returns:
            starting_node: Member node with all its recursive members, with
            the rule appended.
        """
        for node in anytree.iterators.PreOrderIter(starting_node):
            node.rules.append(rule)
        return starting_node

    def _apply_all_rules(self, starting_node, rules):
        """Apply all rules to all the applicable nodes.

        Args:
            starting_node: Member node from which to start appending the rule.
            rules: A list of rules, in dictionary form.

        Returns:
            starting_node: Member node with all the rules applied
               to all the nodes.
        """
        for rule in rules:
            if rule.get('group_email') == MY_CUSTOMER:
                # Apply rule to every node.
                # Because this is simply the root node, there is no need
                # to find this node, i.e. just start at the root.
                # Traversal order should not matter.
                starting_node = self._apply_one_rule(starting_node, rule)
            else:
                # Apply rule to only specific node.
                # Need to find this node.
                # Traversal should not matter since we need to find all
                # instances of the group (because a group can be added
                # to multiple groups).
                #
                # Start at the tree root, find all instances of the specified
                # group, then add the rule to all the members of the specified
                # group.
                for node in anytree.iterators.PreOrderIter(starting_node):
                    if node.member_email == rule.get('group_email'):
                        node = self._apply_one_rule(node, rule)

        return starting_node

    def get_recursive_members(self, starting_node, timestamp):
        """Get all the recursive members of a group.

        Args:
            starting_node: Member node from which to start getting the recursive
                members.
            timestamp: String of snapshot timestamp, formatted as
                YYYYMMDDTHHMMSSZ.

        Returns:
            starting_node: Member node with all its recursive members.
        """
        queue = Queue()
        queue.put(starting_node)

        while not queue.empty():
            queued_node = queue.get()
            members = self.dao.get_group_members('group_members',
                                                 queued_node.member_id,
                                                 timestamp)
            for member in members:
                member_node = MemberNode(member.get('member_id'),
                                         member.get('member_email'),
                                         member.get('member_type'),
                                         member.get('member_status'),
                                         queued_node)
                if member_node.member_type == 'GROUP':
                    queue.put(member_node)

        return starting_node

    def _build_group_tree(self, timestamp):
        """Build a tree of all the groups in the organization.

        Args:
            timestamp: String of snapshot timestamp, formatted as
                YYYYMMDDTHHMMSSZ.

        Returns:
            The root node that holds the tree structure of all the groups
                in the organization.
        """
        root = MemberNode(MY_CUSTOMER, MY_CUSTOMER)

        all_groups = self.dao.get_all_groups('groups', timestamp)
        for group in all_groups:
            group_node = MemberNode(group.get('group_id'),
                                    group.get('group_email'),
                                    'group',
                                    'ACTIVE',
                                    root)
            group_node = self.get_recursive_members(group_node, timestamp)

        LOGGER.debug(anytree.RenderTree(
            root, style=anytree.AsciiStyle()).by_attr('member_email'))

        return root

    def _retrieve(self):
        root = self._build_group_tree(self.snapshot_timestamp)
        return root

    # pylint: disable=arguments-differ
    def run(self):
        """Runs the groups scanner.

        Args:
            rules: String of the path to rules file (yaml/json).

        Returns:
            List of all the nodes in violations.
        """

        root = self._retrieve()

        with open(self.rules, 'r') as f:
            rules = yaml.load(f)

        root = self._apply_all_rules(root, rules)

        all_violations = self.find_violations(root)

        self._output_results(all_violations)
        

class MemberNode(anytree.node.NodeMixin):
    """A custom anytree node with Group Member attributes."""

    def __init__(self, member_id, member_email,
                 member_type=None, member_status=None, parent=None):
        self.member_id = member_id
        self.member_email = member_email
        self.member_type = member_type
        self.member_status = member_status
        self.parent = parent
        self.rules = []
