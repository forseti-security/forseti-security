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

"""Provides the data access object (DAO) for Folders."""

import json

from google.cloud.security.common.data_access import dao
from google.cloud.security.common.data_access.sql_queries import select_data
from google.cloud.security.common.gcp_type import folder as gcp_folder
from google.cloud.security.common.gcp_type import resource
from google.cloud.security.common.gcp_type import resource_util
from google.cloud.security.common.util import log_util

LOGGER = log_util.get_logger(__name__)


class FolderDao(dao.Dao):
    """Data access object (DAO) for Folders."""

    # pylint: disable=arguments-differ
    @staticmethod
    def map_row_to_object(row):
        """Instantiate a Folder from a database row.

        TODO: Make this go away when we start using an ORM.

        Args:
            row: The database row to map to the Folder object.

        Returns:
            A Folder from the database row.
        """
        return gcp_folder.Folder(
            folder_id=row.get('folder_id'),
            name=row.get('name'),
            display_name=row.get('display_name'),
            lifecycle_state=row.get('lifecycle_state'),
            parent=resource_util.create_resource(
                resource_id=row.get('parent_id'),
                resource_type=row.get('parent_type')))
    # pylint: enable=arguments-differ

    def get_folders(self, resource_name, timestamp):
        """Get folders from snapshot table.

        Args:
            timestamp: The timestamp of the snapshot.

        Returns:
            A list of Folders.
        """
        # TODO: remove this when we stop passing resource_name as an arg.
        del resource_name
        query = select_data.FOLDERS.format(timestamp)
        rows = self.execute_sql_with_fetch(
            resource.ResourceType.FOLDER, query, ())
        return [self.map_row_to_object(row) for row in rows]

    def get_folder(self, folder_id, timestamp):
        """Get an folder from the database snapshot.

        Args:
            folder_id: The Folder to retrieve.
            timestamp: The timestamp of the snapshot.

        Returns:
            A Folder from the database snapshot.
        """
        query = select_data.FOLDER_BY_ID.format(timestamp)
        rows = self.execute_sql_with_fetch(
            resource.ResourceType.FOLDER, query, (folder_id,))
        if rows:
            return self.map_row_to_object(rows[0])
        return None

    def get_folder_iam_policies(self, resource_name, timestamp):
        """Get the folder policies.

        This does not raise any errors if there's a database or json parse
        error because we want to return as many folders as possible.

        Args:
            timestamp: The timestamp of the snapshot.

        Returns:
            A dict keyed by the folders
            (gcp_type.folder.Folder) and their iam policies (dict).
        """
        folder_iam_policies = {}
        query = select_data.FOLDER_IAM_POLICIES.format(timestamp, timestamp)
        rows = self.execute_sql_with_fetch(resource_name, query, ())
        for row in rows:
            try:
                folder = gcp_folder.Folder(
                    folder_id=row.get('folder_id'),
                    display_name=row.get('display_name'),
                    lifecycle_state=row.get('lifecycle_state'),
                    parent=resource_util.create_resource(
                        resource_id=row.get('parent_id'),
                        resource_type=row.get('parent_type')))
                iam_policy = json.loads(row.get('iam_policy'))
                folder_iam_policies[folder] = iam_policy
            except ValueError:
                LOGGER.warn('Error parsing json:\n %s', row.get('iam_policy'))

        return folder_iam_policies
