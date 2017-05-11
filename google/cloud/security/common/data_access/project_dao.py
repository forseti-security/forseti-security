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

from google.cloud.security.common.data_access import dao
from google.cloud.security.common.data_access.sql_queries import select_data
from google.cloud.security.common.gcp_type import project
from google.cloud.security.common.gcp_type import resource
from google.cloud.security.common.gcp_type import resource_util
from google.cloud.security.common.util import log_util

LOGGER = log_util.get_logger(__name__)


class ProjectDao(dao.Dao):
    """Data access object (DAO)."""

    # pylint: disable=arguments-differ
    @staticmethod
    def map_row_to_object(row):
        """Instantiate a Project from database row.

        TODO: Make this go away when we start using an ORM.
        ProjectDao has a special case because the database schema doesn't
        match the GCP API fields.

        Args:
            row: The database row to map.

        Returns:
            A Project, created from the row.
        """
        return project.Project(
            project_id=row['project_id'],
            project_number=row['project_number'],
            display_name=row['project_name'],
            lifecycle_state=row['lifecycle_state'],
            parent=resource_util.create_resource(
                resource_id=row['parent_id'],
                resource_type=row['parent_type']))
    # pylint: enable=arguments-differ

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

    def get_project(self, project_id, timestamp):
        """Get a project from a particular snapshot.

        Args:
            project_id: The id of the project.
            timestamp: The snapshot timestamp.

        Returns:
            A Project, if found.
        """
        project_query = select_data.PROJECT_BY_ID.format(timestamp)
        rows = self.execute_sql_with_fetch(
            resource.ResourceType.PROJECT, project_query, (project_id,))
        if rows:
            return self.map_row_to_object(rows[0])
        return None

    def get_projects(self, timestamp):
        """Get projects from a particular snapshot.

        Args:
            timestamp: The snapshot timestamp.

        Returns:
            A list of Projects.

        Raises:
            MySQLError if a MySQL error occurs.
        """
        projects_query = select_data.PROJECTS.format(timestamp)
        rows = self.execute_sql_with_fetch(
            resource.ResourceType.PROJECT, projects_query, ())
        return [self.map_row_to_object(row) for row in rows]

    def get_project_policies(self, resource_name, timestamp):
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
        query = select_data.PROJECT_IAM_POLICIES_RAW.format(
            timestamp, timestamp)
        rows = self.execute_sql_with_fetch(
            resource_name, query, ())
        for row in rows:
            try:
                proj = self.map_row_to_object(row)
                project_policies[proj] = json.loads(row['iam_policy'])
            except ValueError:
                LOGGER.warn('Error parsing json:\n %s', row['iam_policy'])
        return project_policies
