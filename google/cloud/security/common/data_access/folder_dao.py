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

from MySQLdb import DataError
from MySQLdb import IntegrityError
from MySQLdb import InternalError
from MySQLdb import NotSupportedError
from MySQLdb import OperationalError
from MySQLdb import ProgrammingError

from google.cloud.security.common.data_access import dao
from google.cloud.security.common.data_access.errors import MySQLError
from google.cloud.security.common.data_access.sql_queries import select_data
from google.cloud.security.common.gcp_type import folder as gcp_folder
from google.cloud.security.common.gcp_type import resource_util
from google.cloud.security.common.util import log_util

LOGGER = log_util.get_logger(__name__)


class FolderDao(dao.Dao):
    """Data access object (DAO) for Folders."""

    def __init__(self):
        super(FolderDao, self).__init__()

    def get_folders(self, resource_name, timestamp):
        """Get folders from snapshot table.

        Args:
            timestamp: The timestamp of the snapshot.

        Returns:
            A list of Folders.

        Raise:
            MySQLError if there's an error fetching the folders.
        """
        try:
            cursor = self.conn.cursor()
            cursor.execute(select_data.FOLDERS.format(timestamp))
            rows = cursor.fetchall()
            folders = []
            for row in rows:
                folder_parent = None
                if row[6] and row[5]:
                    folder_parent = (
                        resource_util.ResourceUtil.create_resource(
                            resource_id=row[6],
                            resource_type=row[5]))
                folder = gcp_folder.Folder(
                    folder_id=row[0],
                    display_name=row[2],
                    lifecycle_state=row[3],
                    parent=folder_parent)
                folders.append(folder)
            return folders
        except (DataError, IntegrityError, InternalError, NotSupportedError,
                OperationalError, ProgrammingError) as e:
            raise MySQLError(resource_name, e)

    def get_folder(self, timestamp, folder_id):
        """Get an folder from the database snapshot.

        Args:
            timestamp: The timestamp of the snapshot.
            folder_id: The Folder to retrieve.

        Returns:
            A Folder from the database snapshot.

        Raises:
            MySQLError if there was an error getting the folder.
        """
        try:
            cursor = self.conn.cursor()
            query = select_data.FOLDER_BY_ID.format(timestamp)
            cursor.execute(query, folder_id)
            row = cursor.fetchone()
            folder_parent = None
            if row[6] and row[5]:
                folder_parent = (
                    resource_util.ResourceUtil.create_resource(
                        resource_id=row[6],
                        resource_type=row[5]))
            folder = gcp_folder.Folder(
                folder_id=row[0],
                display_name=row[2],
                lifecycle_state=row[3],
                parent=folder_parent)
            return folder
        except (DataError, IntegrityError, InternalError, NotSupportedError,
                OperationalError, ProgrammingError) as e:
            raise MySQLError(folder_id, e)

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
        try:
            cursor = self.conn.cursor()
            cursor.execute(
                select_data.FOLDER_IAM_POLICIES.format(timestamp, timestamp))
            rows = cursor.fetchall()
            for row in rows:
                try:
                    folder_parent = None
                    if row[4] and row[3]:
                        folder_parent = (
                            resource_util.ResourceUtil.create_resource(
                                resource_id=row[4],
                                resource_type=row[3]))
                    folder = gcp_folder.Folder(
                        folder_id=row[0],
                        display_name=row[1],
                        lifecycle_state=row[2],
                        parent=folder_parent)
                    iam_policy = json.loads(row[5])
                    folder_iam_policies[folder] = iam_policy
                except ValueError:
                    LOGGER.warn('Error parsing json:\n %s', row[5])
        except (DataError, IntegrityError, InternalError, NotSupportedError,
                OperationalError, ProgrammingError) as e:
            LOGGER.error(MySQLError(resource_name, e))
        return folder_iam_policies
