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

"""Pipeline to load GSuite Account Groups into Inventory."""

from oauth2client.contrib.gce import AppAssertionCredentials
from oauth2client.service_account import ServiceAccountCredentials

from google.cloud.security.common.data_access.errors import CSVFileError
from google.cloud.security.common.data_access.errors import MySQLError
from google.cloud.security.common.gcp_api._base_client import ApiExecutionError
# TODO: Investigate improving so the pylint disable isn't needed.
# pylint: disable=line-too-long
from google.cloud.security.common.gcp_api.admin_directory import AdminDirectoryClient
from google.cloud.security.common.util import metadata_server
from google.cloud.security.common.util.log_util import LogUtil
from google.cloud.security.inventory import transform_util
from google.cloud.security.inventory.errors import LoadDataPipelineError


LOGGER = LogUtil.setup_logging(__name__)
RESOURCE_NAME = 'groups'
REQUIRED_SCOPES = ['https://www.googleapis.com/auth/admin.directory.user',
                   'https://www.googleapis.com/auth/admin.directory.group']


def _build_proper_credentials(configs):
    """Build proper credentials required for accessing the directory API.

    Args:
        configs: Dictionary of configurations.

    Returns:
        Credentials as built by oauth2client.
    """

    if metadata_server.can_reach_metadata_server():
        return AppAssertionCredentials(REQUIRED_SCOPES)

    credentials = ServiceAccountCredentials.from_json_keyfile_name(
        configs.get('service_account_credentials_file'),
        scopes=REQUIRED_SCOPES)

    return credentials.create_delegated(
        configs.get('domain_super_admin_email'))


def run(dao=None, cycle_timestamp=None, configs=None, crm_rate_limiter=None):
    """Runs the load GSuite account groups pipeline.

    Args:
        dao: Data access object.
        cycle_timestamp: String of timestamp, formatted as YYYYMMDDTHHMMSSZ.
        configs: Dictionary of configurations.
        crm_rate_limiter: RateLimiter object for CRM API client.

    Returns:
        None

    Raises:
        LoadDataPipelineException: An error with loading data has occurred.
    """
    credentials = _build_proper_credentials(configs)
    admin_client = AdminDirectoryClient(credentials=credentials,
                                        rate_limiter=crm_rate_limiter)

    try:
        groups_map = admin_client.get_groups()
        print groups_map
    except ApiExecutionError as e:
        raise LoadDataPipelineError(e)

    flattended_groups = transform_util.flatten_groups(groups_map)
    print flatten_groups

    try:
        dao.load_data(RESOURCE_NAME, cycle_timestamp, flattended_groups)
    except (CSVFileError, MySQLError) as e:
        raise LoadDataPipelineError(e)
