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
from anytree.node import NodeMixin

"""Provides the data access object (DAO) for Groups."""

from Queue import Queue

from anytree import Node
from anytree import RenderTree
from anytree import AsciiStyle

from google.cloud.security.common.data_access import dao
from google.cloud.security.common.data_access.sql_queries import select_data
from google.cloud.security.common.util import log_util

LOGGER = log_util.get_logger(__name__)


class GroupDao(dao.Dao):
    """Data access object (DAO) for Groups."""

    def get_all_groups(self, resource_name, timestamp):
        sql = select_data.GROUPS.format(timestamp)
        result = self.execute_sql_with_fetch(resource_name, sql, None)
        return result



    def get_group_id(self, resource_name, group_email, timestamp):
        """Get the group_id for the specified group_email.

        Args:
            resource_name: String of the resource name.
            group_email: String of the group email.
            timestamp: The timestamp of the snapshot.

        Returns:
             String of the group id.
        """
        sql = select_data.GROUP_ID.format(timestamp)
        result = self.execute_sql_with_fetch(resource_name, sql, (group_email,))
        return result[0].get('group_id')

    def get_group_members(self, resource_name, group_id, timestamp):
        """Get the members of a group.

        Args:
            resource_name: String of the resource name.
            group_id: String of the group id.
            timestamp: The timestamp of the snapshot.

        Returns:
             A tuple of group members in dict format.
             ({'group_id': '00lnxb',
               'member_email': 'foo@mygbiz.com',
               'member_id': '11111',
               'member_role': 'OWNER',
               'member_type': 'USER'}, ...)
        """
        sql = select_data.GROUP_MEMBERS.format(timestamp)
        return self.execute_sql_with_fetch(resource_name, sql, (group_id,))

    def get_recursive_members_of_group(self, group_email, timestamp):
        """Get all the recursive members of a group.

        Args:
            group_email: String of the group email.
            timestamp: The timestamp of the snapshot.

        Returns:
             A list of group members in dict format.
             [{'group_id': '00lnxb',
               'member_email': 'foo@mygbiz.com',
               'member_id': '11111',
               'member_role': 'OWNER',
               'member_type': 'USER'}, ...]
        """
        all_members = []
        queue = Queue()

        group_id = self.get_group_id('group', group_email, timestamp)
        queue.put(group_id)

        while not queue.empty():
            group_id = queue.get()
            members = self.get_group_members('group_members', group_id,
                                             timestamp)
            for member in members:
                all_members.append(member)
                if member.get('member_type') == 'GROUP':
                    queue.put(member.get('member_id'))
        return all_members

    def get_recursive_members_of_group_node(self, group_node, timestamp):

        queue = Queue()
        queue.put(group_node)
        
        while not queue.empty():
            group_node = queue.get()
            members = self.get_group_members('group_members', group_node.member_id,
                                             timestamp)

            for member in members:
                member_node = MemberNode(member.get('member_id'),
                                         member.get('member_email'),
                                         member.get('member_type'),
                                         member.get('member_satus'),
                                         group_node)
                if member_node.member_type == 'GROUP':
                    queue.put(member_node)
        
        return group_node

    def build_group_tree(self, timestamp):
        """Build a tree of all the groups in the organization.

        Args:
            timestamp: String of snapshot timestamp, formatted as
                YYYYMMDDTHHMMSSZ.

        Returns:
            A tree (represented as the root node) of all the groups
                in the organization.
        """
        root = MemberNode('my_customer', 'my_customer', None, None, None)
        
        all_groups = self.get_all_groups('groups', timestamp)
        for group in all_groups:
            group_node = MemberNode(group.get('group_id'),
                                    group.get('group_email'),
                                    'group',
                                    'ACTIVE',
                                    root)
            group_node = self.get_recursive_members_of_group_node(group_node,
                                                                  timestamp)
        
        LOGGER.info(RenderTree(root, style=AsciiStyle()).by_attr(
            'member_email'))
        return root


class MemberNode(NodeMixin):
    """A custom anytree node with Group Member attributes."""
    
    def __init__(self, member_id, member_email, member_type, member_status, parent):
        self.member_id = member_id
        self.member_email = member_email
        self.member_type = member_type
        self.member_status = member_status
        self.parent = parent
        self.rules = []
