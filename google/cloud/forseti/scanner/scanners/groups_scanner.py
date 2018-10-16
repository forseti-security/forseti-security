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

"""Scanner for Google Groups."""

import anytree

from google.cloud.forseti.common.util import logger
from google.cloud.forseti.common.util import file_loader
from google.cloud.forseti.scanner.scanners import base_scanner


LOGGER = logger.get_logger(__name__)
MY_CUSTOMER = 'my_customer'


class GroupsScanner(base_scanner.BaseScanner):
    """Scanner for group members data."""

    @staticmethod
    def _flatten_violations(violations):
        """Flatten RuleViolations into a dict for each RuleViolation member.

        Args:
            violations (list): The RuleViolations to flatten.

        Yields:
            dict: Iterator of RuleViolations as a dict per member.
        """
        for violation in violations:
            violation_data = {
                'violated_rule_names': violation.violated_rule_names,
                'member_email': violation.member_email,
                'member_id': violation.member_id,
                'member_status': violation.member_status,
                'member_type': violation.member_type,
                'parent_email': violation.parent.member_email,
                'parent_id': violation.parent.member_id,
                'parent_status': violation.parent.member_status,
                'parent_resource_type': violation.parent.member_type
            }
            full_name = violation.parent.member_id + ':' + violation.member_id
            yield {
                'resource_id': violation.member_email,
                'resource_name': violation.member_email,
                'resource_type': 'group_member',
                'full_name': full_name,
                'rule_index': None,
                'rule_name': violation.violated_rule_names,
                'violation_type': 'GROUP_VIOLATION',
                'violation_data': violation_data,
                'resource_data': violation.resource_data
            }

    def _output_results(self, all_violations):
        """Output results.

        Args:
            all_violations (list): A list of nodes that are in violation.
        """
        all_violations = self._flatten_violations(all_violations)
        self._output_results_to_db(all_violations)

    # pylint: disable=too-many-branches
    @staticmethod
    def _find_violations(root):
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
            root (node): The nodes (tree structure) to find violations in.

        Returns:
            list: Nodes that are in violation.
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

            # Skip the member if there is no rules to check against.
            if not node.rules:
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
            if not any(whitelist_rule_statuses):
                all_violations.append(node)

        return all_violations

    @staticmethod
    def _apply_one_rule(starting_node, rule):
        """Append the rule to all the applicable nodes.

        Args:
            starting_node (node): Member node from which to start appending
                the rule.
            rule (dict): A dictionary representation of a rule.

        Returns:
            node: Member node with all its recursive members,
                with the rule appended.
        """
        for node in anytree.iterators.PreOrderIter(starting_node):
            node.rules.append(rule)
        return starting_node

    def _apply_all_rules(self, starting_node, group_rules):
        """Apply all rules to all the applicable nodes.

        Args:
            starting_node (node): Member node from which to start appending the
                rule.
            group_rules (dict): A list of rules, in dictionary form.

        Returns:
            node: Member node with all the rules applied to all the nodes.
        """
        for rule in group_rules:
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
                        self._apply_one_rule(node, rule)
                        break  # Avoid visiting the same group more than once.

        return starting_node

    def _get_recursive_members(self, starting_node):
        """Get all the recursive members of a group.

        Args:
            starting_node (node): Member node from which to start getting
                the recursive members.
        """
        model_manager = self.service_config.model_manager
        scoped_session, data_access = model_manager.get(self.model_name)
        with scoped_session as session:
            members = data_access.expand_members(session,
                                                 [starting_node.member_id])
            for member in members:
                MemberNode(member.name,
                           member.member_name,
                           member.type,
                           'ACTIVE',
                           starting_node)

    def _build_group_tree(self):
        """Build a tree of all the groups in the organization.

        Returns:
            node: The tree structure of all the groups in the organization.
        """
        root = MemberNode(MY_CUSTOMER, MY_CUSTOMER)
        model_manager = self.service_config.model_manager
        scoped_session, data_access = model_manager.get(self.model_name)
        with scoped_session as session:
            all_groups = data_access.iter_groups(session)

            for group in all_groups:
                group_node = MemberNode(group.name,
                                        group.member_name,
                                        group.type,
                                        'ACTIVE',
                                        root)
                self._get_recursive_members(group_node)

        LOGGER.debug(anytree.RenderTree(
            root, style=anytree.AsciiStyle()).by_attr('member_email'))

        return root

    def _retrieve(self):
        """Retrieves the group tree.

        Args:
            None

        Returns:
            node: The tree structure of all the groups in the organization.
        """
        root = self._build_group_tree()
        return root

    def run(self):
        """Runs the groups scanner."""

        root = self._retrieve()

        group_rules = file_loader.read_and_parse_file(self.rules)

        root = self._apply_all_rules(root, group_rules)

        all_violations = self._find_violations(root)

        self._output_results(all_violations)


class MemberNode(anytree.node.NodeMixin):
    """A custom anytree node with Group Member attributes."""

    def __init__(self, member_id, member_email,
                 member_type=None, member_status=None, parent=None,):
        """Initialization.

        Args:
            member_id (str): id of the member
            member_email (str): email of the member
            member_type (str): type of the member
            member_status (str): status of the member
            parent (node): parent node
        """
        self.member_id = member_id
        self.member_email = member_email
        self.resource_data = member_email
        self.member_type = member_type
        self.member_status = member_status
        self.parent = parent
        self.rules = []
