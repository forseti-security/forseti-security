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

"""Provides the data access object (DAO) for CloudSQL."""

from MySQLdb import DataError
from MySQLdb import IntegrityError
from MySQLdb import InternalError
from MySQLdb import NotSupportedError
from MySQLdb import OperationalError
from MySQLdb import ProgrammingError

from google.cloud.security.common.data_access import project_dao
from google.cloud.security.common.data_access import errors
from google.cloud.security.common.data_access.sql_queries import select_data
from google.cloud.security.common.util import log_util
# pylint: disable=line-too-long
from google.cloud.security.common.gcp_type import cloudsql_access_controls as csql_acls
# pylint: enable=line-too-long

LOGGER = log_util.get_logger(__name__)


class CloudsqlDao(project_dao.ProjectDao):
    """Data access object (DAO) for CloudSQL."""

    def __init__(self):
        super(CloudsqlDao, self).__init__()

    def get_cloudsql_acls(self, resource_name, timestamp):
        """Select the cloudsql acls for project from a snapshot table.

        Args:
            resource_name: String of the resource name.
            timestamp: String of timestamp, formatted as YYYYMMDDTHHMMSSZ.

        Returns:
            List of cloudsql acls.

        Raises:
            MySQLError: An error with MySQL has occurred.
        """
        cloudsql_acls = {}
        cnt = 0
        try:
            cloudsql_instances_sql = (
                select_data.CLOUDSQL_INSTANCES.format(timestamp))
            rows = self.execute_sql_with_fetch(resource_name,
                                               cloudsql_instances_sql,
                                               None)
            acl_map = self._get_cloudsql_instance_acl_map(resource_name,
                                                          timestamp)

            for row in rows:
                project_number = row['project_number']
                instance_name = row['name']
                ssl_enabled = row['settings_ip_configuration_require_ssl']
                authorized_networks = self.\
                _get_networks_for_instance(acl_map,
                                           project_number,
                                           instance_name)

                cloudsql_acl = csql_acls.\
                CloudSqlAccessControl(instance_name=instance_name,
                                      authorized_networks=authorized_networks,
                                      ssl_enabled=ssl_enabled,
                                      project_number=project_number)
                cloudsql_acls[cnt] = cloudsql_acl
                cnt += 1
        except (DataError, IntegrityError, InternalError, NotSupportedError,
                OperationalError, ProgrammingError) as e:
            LOGGER.error(errors.MySQLError(resource_name, e))
        return cloudsql_acls

    def _get_cloudsql_instance_acl_map(self, resource_name, timestamp):
        """Create CloudSQL instance acl map.

        Args:
            resource_name: String of the resource name.
            timestamp: String of timestamp, formatted as YYYYMMDDTHHMMSSZ.

        Returns:
            Map of instance acls.

        Raises:
            MySQLError: An error with MySQL has occurred.
        """
        cloudsql_acls_map = {}
        try:
            cloudsql_acls_sql = select_data.CLOUDSQL_ACLS.format(timestamp)
            rows = self.execute_sql_with_fetch(resource_name,
                                               cloudsql_acls_sql,
                                               None)
            for row in rows:
                acl_list = []
                project_number = row['project_number']
                instance_name = row['instance_name']
                network = row['value']
                hash_key = hash(str(project_number) + ',' + instance_name)
                if hash_key in cloudsql_acls_map:
                    if network not in cloudsql_acls_map[hash_key]:
                        cloudsql_acls_map[hash_key].append(network)
                else:
                    acl_list.append(network)
                    cloudsql_acls_map[hash_key] = acl_list
        except (DataError, IntegrityError, InternalError, NotSupportedError,
                OperationalError, ProgrammingError) as e:
            LOGGER.error(errors.MySQLError(resource_name, e))

        return cloudsql_acls_map

    def _get_networks_for_instance(self, acl_map, project_number,
                                   instance_name):
        """Create a list of authorized networks for instance

        Args:
            acl_map: acl map
            project_number: project number
            instance_name: name of the instance

        Returns:
            List of authorizes networks
        """
        authorized_networks = []
        hash_key = hash(str(project_number) + ',' + instance_name)
        if hash_key in acl_map:
            authorized_networks = acl_map[hash_key]
        return authorized_networks
