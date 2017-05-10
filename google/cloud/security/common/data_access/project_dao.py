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

from google.cloud.security.common.data_access import dao
from google.cloud.security.common.data_access import errors
from google.cloud.security.common.data_access.sql_queries import select_data
from google.cloud.security.common.gcp_type import project
from google.cloud.security.common.gcp_type import resource_util
from google.cloud.security.common.util import log_util

LOGGER = log_util.get_logger(__name__)


class ProjectDao(dao.Dao):
    """Data access object (DAO)."""

    def get_project_numbers(self, resource_name, timestamp):
        """Select the project numbers from a projects snapshot table.

        Args:
            resource_name: String of the resource name.
            timestamp: String of timestamp, formatted as YYYYMMDDTHHMMSSZ.

        Returns:
             list of project numbers

        Raises:
            MySQLError: An error with MySQL has occurred.
        """
        project_numbers_sql = select_data.PROJECT_NUMBERS.format(timestamp)
        rows = self.execute_sql_with_fetch(
            resource_name, project_numbers_sql, ())
        return [row['project_number'] for row in rows]

    def get_project_policies(self, resource_name, timestamp,):
        """Get the project policies.

        This does not raise any errors on database or json parse errors
        because we want to return as many projects as possible.

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
                    proj_parent = None
                    if row[5] and row[4]:
                        proj_parent = (
                            resource_util.ResourceUtil.create_resource(
                                resource_id=row[5],
                                resource_type=row[4]))
                    proj = project.Project(
                        project_id=row[1],
                        project_number=row[0],
                        display_name=row[2],
                        lifecycle_state=row[3],
                        parent=proj_parent)
                    iam_policy = json.loads(row[6])
                    project_policies[proj] = iam_policy
                except ValueError:
                    LOGGER.warn('Error parsing json:\n %s', row[6])
        except (DataError, IntegrityError, InternalError, NotSupportedError,
                OperationalError, ProgrammingError) as e:
            LOGGER.error(errors.MySQLError(resource_name, e))
        return project_policies

    def get_project_raw_data(self, resource_name, timestamp, **kwargs):
        """Select the project raw data from a projects snapshot table.

        Args:
            resource_name: String of the resource name.
            timestamp: String of timestamp, formatted as YYYYMMDDTHHMMSSZ.
            project_id (optional): project_id for specific project

        Returns:
             list of project numbers

        Raises:
            MySQLError: An error with MySQL has occurred.
        """
        project_id = kwargs.get('project_id')
        if project_id is not None:
            project_raw_sql = select_data.PROJECT_RAW.format(timestamp)
            rows = self.execute_sql_with_fetch(
                resource_name, project_raw_sql, (project_id,))
        else:
            project_raw_sql = select_data.PROJECT_RAW_ALL.format(timestamp)
            rows = self.execute_sql_with_fetch(
                resource_name, project_raw_sql, ())
        return [row['raw_project'] for row in rows]
