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

"""Provides the data access object (DAO)."""

import json

from google.cloud.forseti.common.data_access import dao
from google.cloud.forseti.common.data_access.sql_queries import select_data
from google.cloud.forseti.common.gcp_type import project
from google.cloud.forseti.common.gcp_type import resource
from google.cloud.forseti.common.gcp_type import resource_util
from google.cloud.forseti.common.util import log_util


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
            row (dict): The database row to map.

        Returns:
            Project: A Project, created from the row.
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
            resource_name (str): The resource name.
            timestamp (str): The timestamp, formatted as YYYYMMDDTHHMMSSZ.

        Returns:
             list: A list of project numbers.

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
            project_id (str): The id of the project.
            timestamp (str): The snapshot timestamp.

        Returns:
            Project: A Project, if found.
        """
        project_query = select_data.PROJECT_BY_ID.format(timestamp)
        rows = self.execute_sql_with_fetch(
            resource.ResourceType.PROJECT, project_query, (project_id,))
        if rows:
            return self.map_row_to_object(rows[0])
        return None

    def get_project_by_number(self, project_number, timestamp):
        """Get a project from a particular snapshot.

        Args:
            project_number (int): The number of the project.
            timestamp (str): The snapshot timestamp.

        Returns:
            Project: A Project, if found.
        """
        project_query = select_data.PROJECT_BY_NUMBER.format(timestamp)
        rows = self.execute_sql_with_fetch(
            resource.ResourceType.PROJECT, project_query, (project_number,))
        if rows:
            return self.map_row_to_object(rows[0])
        return None

    def get_all(self, timestamp=None):
        """Get projects from a particular snapshot. Generic method name.

        Args:
            timestamp (str): The snapshot timestamp.

        Returns:
            list: A list of Projects.
        """
        if not timestamp:
            timestamp = self.get_latest_snapshot_timestamp(
                ('SUCCESS', 'PARTIAL_SUCCESS'))
        return self.get_projects(timestamp)

    def get_projects(self, timestamp):
        """Get projects from a particular snapshot.

        Args:
            timestamp (str): The snapshot timestamp.

        Returns:
            list: A list of Projects.
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
            resource_name (str): The resource type.
            timestamp (str): The timestamp of the snapshot.

        Returns:
            dict: A dict containing the projects (gcp_type.project.Project)
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

    def get_project_raw_data(self, resource_name, timestamp, **kwargs):
        """Select the project raw data from a projects snapshot table.

        Args:
            resource_name (str): The resource name.
            timestamp (str): Snapshot timestamp, formatted as YYYYMMDDTHHMMSSZ.
            **kwargs (dict): Additional args.

        Returns:
             list: List of project raw data.
        """
        project_id = kwargs.get('project_id')
        project_number = kwargs.get('project_number')
        if project_id is not None:
            project_raw_sql = select_data.PROJECT_RAW.format(timestamp)
            rows = self.execute_sql_with_fetch(
                resource_name, project_raw_sql, (project_id,))
        elif project_number is not None:
            project_raw_sql = select_data.PROJECT_RAW_BY_NUMBER.format(
                timestamp)
            rows = self.execute_sql_with_fetch(
                resource_name, project_raw_sql, (project_number,))
        else:
            project_raw_sql = select_data.PROJECT_RAW_ALL.format(timestamp)
            rows = self.execute_sql_with_fetch(
                resource_name, project_raw_sql, ())
        return [row['raw_project'] for row in rows]
