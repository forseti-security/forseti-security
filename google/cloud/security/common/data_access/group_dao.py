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

"""Provides the data access object (DAO) for Groups."""

from google.cloud.security.common.data_access import dao
from google.cloud.security.common.data_access.sql_queries import select_data
from google.cloud.security.common.gcp_type import group_member
from google.cloud.security.common.util import log_util

LOGGER = log_util.get_logger(__name__)


class GroupDao(dao.Dao):
    """Data access object (DAO) for Organizations."""

    def __init__(self):
        super(GroupDao, self).__init__()

    def get_group_users(self, resource_name, timestamp):
        """Get the group members who are users.

        Args:
            timestamp: The timestamp of the snapshot.

        Returns:
             A dict containing the group (gcp_type.group) and a list of
            their members (gcp_type.group_members) who are user type.
        """
        sql = select_data.GROUP_USERS.format(timestamp)
        rows = self.execute_sql_with_fetch(resource_name, sql, None)
        group_users = {}
        for row in rows:
            # TODO: Determine if parenting is needed here, similar to
            # project IAM policies.
            group_user = group_member.GroupMember(
                row.get('member_role'),
                row.get('member_type'),
                row.get('member_id'))
            if row.get('group_id') not in group_users:
                group_users[row.get('group_id')] = [group_user]
            else:
                group_users[row.get('group_id')].append(group_user)
        return group_users
