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

"""Provides the data access object (DAO) for Groups."""

from Queue import Queue

from google.cloud.forseti.common.data_access import dao
from google.cloud.forseti.common.data_access.sql_queries import select_data
from google.cloud.forseti.common.util import log_util


LOGGER = log_util.get_logger(__name__)
MY_CUSTOMER = 'my_customer'


class GroupDao(dao.Dao):
    """Data access object (DAO) for Groups."""

    def get_all_groups(self, resource_name, timestamp):
        """Get all the groups.

        Args:
            resource_name (str): The resource name.
            timestamp (str): The timestamp of the snapshot.

        Returns:
             tuple: A tuple with group data as dict.
        """
        sql = select_data.GROUPS.format(timestamp)
        return self.execute_sql_with_fetch(resource_name, sql, None)

    def get_group_id(self, resource_name, group_email, timestamp):
        """Get the group_id for the specified group_email.

        Args:
            resource_name (str): The resource name.
            group_email (str): The group email.
            timestamp (str): The timestamp of the snapshot.

        Returns:
             str: String of the group id.
        """
        sql = select_data.GROUP_ID.format(timestamp)
        result = self.execute_sql_with_fetch(resource_name, sql, (group_email,))
        return result[0].get('group_id')

    def get_group_members(self, resource_name, group_id, timestamp):
        """Get the members of a group.

        Args:
            resource_name (str): The resource name.
            group_id (str): The group id.
            timestamp (str): The timestamp of the snapshot.

        Returns:
             tuple: A tuple of group members in dict format.

             ({'group_id': '00lnxb',
               'member_email': 'foo@company.com',
               'member_id': '11111',
               'member_role': 'OWNER',
               'member_type': 'USER'}, ...)
        """
        sql = select_data.GROUP_MEMBERS.format(timestamp)
        return self.execute_sql_with_fetch(resource_name, sql, (group_id,))

    def get_recursive_members_of_group(self, group_email, timestamp):
        """Get all the recursive members of a group.

        Args:
            group_email (str): The group email.
            timestamp (str): The timestamp of the snapshot.

        Returns:
             list: A list of group members in dict format.

             [{'group_id': '00lnxb',
               'member_email': 'foo@company.com',
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
