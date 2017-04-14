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

import json

from MySQLdb import DataError
from MySQLdb import IntegrityError
from MySQLdb import InternalError
from MySQLdb import NotSupportedError
from MySQLdb import OperationalError
from MySQLdb import ProgrammingError

from google.cloud.security.common.data_access import _db_connector
from google.cloud.security.common.data_access import errors
from google.cloud.security.common.data_access.sql_queries import select_data
from google.cloud.security.common.gcp_type import project
from google.cloud.security.common.gcp_type import resource_util
from google.cloud.security.common.util import log_util

LOGGER = log_util.get_logger(__name__)


class ProjectDao(_db_connector.DbConnector):
    """Data access object (DAO)."""

    def __init__(self):
        super(ProjectDao, self).__init__()

    def get_project_policies(self, resource_name, timestamp):
        """Get the project policies.

        Args:
            resource_name: The resource type.
            timestamp: The timestamp of the snapshot.

        Returns:
            A dict containing the projects (gcp_type.project.Project)
            and their iam policies (dict).
        """
        project_policies = {}
        try:
            cursor = self.conn.cursor()
            cursor.execute(
                select_data.PROJECT_IAM_POLICIES_RAW.format(
                    timestamp, timestamp))
            rows = cursor.fetchall()
            for row in rows:
                try:
                    proj = project.Project(
                        project_id=row[1],
                        project_name=row[2],
                        project_number=row[0],
                        lifecycle_state=row[3])
                    if row[5] and row[4]:
                        proj.parent = (
                            resource_util.ResourceUtil.create_resource(
                                resource_id=row[5],
                                resource_type=row[4]))
                    iam_policy = json.loads(row[6])
                    project_policies[proj] = iam_policy
                except ValueError:
                    LOGGER.warn('Error parsing json:\n %s', row[6])
        except (DataError, IntegrityError, InternalError, NotSupportedError,
                OperationalError, ProgrammingError) as e:
            LOGGER.error(errors.MySQLError(resource_name, e))
        return project_policies
