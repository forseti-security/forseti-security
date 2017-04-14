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

"""Provides the data access object (DAO)."""

from MySQLdb import DataError
from MySQLdb import IntegrityError
from MySQLdb import InternalError
from MySQLdb import NotSupportedError
from MySQLdb import OperationalError
from MySQLdb import ProgrammingError

from google.cloud.security.common.data_access import _db_connector
from google.cloud.security.common.data_access.errors import MySQLError
from google.cloud.security.common.data_access.sql_queries import select_data
from google.cloud.security.common.gcp_type.project import Project
from google.cloud.security.common.gcp_type.resource_util import ResourceUtil
from google.cloud.security.common.util import log_util

LOGGER = log_util.get_logger(__name__)


class ProjectDao(_db_connector.DbConnector):
    """Data access object (DAO)."""

    def __init__(self):
        super(ProjectDao, self).__init__()

    # pylint: disable=too-many-locals
    # TODO: Look into lowering variabls to remove pylint disable.
    def get_project_policies(self, timestamp):
        """Get the project policies.

        Args:
            timestamp: The timestamp of the snapshot.

        Returns:
            A dict containing the projects (gcp_type.project.Project)
            and their iam policies (dict).
        """
        project_policies = {}
        prev_proj_id = None
        prev_proj = None
        try:
            cursor = self.conn.cursor()
            cursor.execute(select_data.PROJECT_IAM_POLICIES.format(
                timestamp, timestamp))
            rows = cursor.fetchall()
            for row in rows:
                proj_id = row[1]
                if prev_proj_id != proj_id:
                    project = Project(project_id=row[1],
                                      project_name=row[2],
                                      project_number=row[0],
                                      lifecycle_state=row[3])
                    project.parent = ResourceUtil.create_resource(
                        resource_id=row[5],
                        resource_type=row[4])
                else:
                    project = prev_proj
                policy = project_policies.get(project)
                if not policy:
                    policy = {
                        'bindings': []
                    }

                role = row[6]
                member_type = row[7]
                member_name = row[8]
                member_domain = row[9]
                member = ''
                if member_name:
                    member = '{}:{}@{}'.format(
                        member_type, member_name, member_domain)
                else:
                    member = '{}:{}'.format(member_type, member_domain)

                member = member.strip()
                added_to_role = False

                for binding in policy.get('bindings'):
                    if binding.get('role') == role:
                        binding.get('members').append(member)
                        added_to_role = True

                if not added_to_role:
                    policy['bindings'].append({
                        'role': role,
                        'members': [member]
                    })

                project_policies[project] = policy
                prev_proj = project
        except (DataError, IntegrityError, InternalError, NotSupportedError,
                OperationalError, ProgrammingError) as e:
            LOGGER.error(MySQLError('projects', e))
        return project_policies
