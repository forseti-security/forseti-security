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

from anytree import iterators
import yaml

from google.cloud.security.common.util import log_util
from google.cloud.security.common.data_access import group_dao
from google.cloud.security.scanner.scanners import base_scanner


LOGGER = log_util.get_logger(__name__)


class GroupsScanner(base_scanner.BaseScanner):
    """Pipeline to IAM data from DAO"""

    def __init__(self, snapshot_timestamp):
        """Constructor for the base pipeline.

        Args:
            snapshot_timestamp: String of timestamp, formatted as
                YYYYMMDDTHHMMSSZ.

        Returns:
            None
        """
        super(GroupsScanner, self).__init__(
            snapshot_timestamp)

    @staticmethod
    def _append_rule(starting_node, rule):
        """Append the rule to all the applicable nodes.

        Args:
            starting_node: Member node from which to start appending the rule.
            timestamp: String of snapshot timestamp, formatted as
                YYYYMMDDTHHMMSSZ.

        Returns:
            starting_node: Member node with all its recursive members, with
            the rule appended.
        """
        for node in iterators.PreOrderIter(starting_node):
            node.rules.append(rule)
        return starting_node

    def run(self):
        """Runs the groups scanner."""

        dao = group_dao.GroupDao()
        root = dao.build_group_tree(self.snapshot_timestamp)

        rules_path = 'google/cloud/security/scanner/samples/group_rules.yaml'
        with open(rules_path, 'r') as f:
            rules = yaml.load(f)
    
        # Apply all rules to applicable nodes.
        for rule in rules:
            if rule.get('group_email') == 'my_customer':
                # Apply rule to every node.
                # Because this is simply the root node, there is no need
                # to find this node, i.e. just start at the root.
                # Traversal order should not matter.
                root = self._append_rule(root, rule)
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
                for node in iterators.PreOrderIter(root):
                    if node.member_email == rule.get('group_email'):
                        node = self._append_rule(node, rule)

        return self.find_violations(root)


    def find_violations(self, root):  # pylint: disable=arguments-differ
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
            root: The list of policies to find violations in.

        Returns:
            A list of nodes that are in violation.
        """
        all_violations = []
        for node in iterators.PreOrderIter(root):

            # No need to evaluate these nodes.
            # This represents the org, i.e. is not a group.
            if node.member_email == 'my_customer':
                continue
            # This represents the auto-generated group, containing all the users
            # in the org.
            if node.member_email == '':
                continue

            node.violations = []
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
                    if any(condition_statuses) is True:
                        whitelist_rule_statuses.append(True)
                    else:
                        whitelist_rule_statuses.append(False)

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
            # +-----------------------------------------+---------+---------+
            # |                                         |   any   |   all   |
            # +-----------------------------------------+---------+---------+
            # | All Truthy values                       |  True   |  True   |
            # +-----------------------------------------+---------+---------+
            # | All Falsy values                        |  False  |  False  |
            # +-----------------------------------------+---------+---------+
            # | One Truthy value (all others are Falsy) |  True   |  False  |
            # +-----------------------------------------+---------+---------+
            # | One Falsy value (all others are Truthy) |  True   |  False  |
            # +-----------------------------------------+---------+---------+
            # | Empty Iterable                          |  False  |  True   |
            # +-----------------------------------------+---------+---------+
            if any(whitelist_rule_statuses) is False:
                all_violations.append(node)

        return all_violations
