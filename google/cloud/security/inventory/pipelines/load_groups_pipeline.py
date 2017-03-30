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
# pylint: enable=line-too-long
from google.cloud.security.common.util import metadata_server
from google.cloud.security.common.util.log_util import LogUtil
from google.cloud.security.inventory import transform_util
from google.cloud.security.inventory.errors import LoadDataPipelineError


LOGGER = LogUtil.setup_logging(__name__)
RESOURCE_NAME = 'groups'
REQUIRED_SCOPES = frozenset([
    'https://www.googleapis.com/auth/admin.directory.group.readonly'
])


def _is_our_environment_gce():
    """A simple function that returns a boolean if we're running in GCE."""
    return metadata_server.can_reach_metadata_server()

def _can_inventory_google_groups(config):
    """A simple function that validates required inputs for inventorying groups.

    Args:
        config: Dictionary of configurations built from our config.

    Returns:
        Boolean
    """
    # TODO: We should fetch service_account_email (when on GCE) from the
    # metadata server and not require the flag.
    required_gcp_execution_config = [
        config.get('service_account_email'),
        config.get('domain_super_admin_email')]

    required_local_execution_config = [
        config.get('service_account_email'),
        config.get('service_account_credentials_file'),
        config.get('domain_super_admin_email')]

    if _is_our_environment_gce():
        required_execution_config = required_gcp_execution_config
    else:
        required_execution_config = required_local_execution_config

    return all(required_execution_config)

def _build_proper_credentials(config):
    """Build proper credentials required for accessing the directory API.

    Args:
        config: Dictionary of configurations.

    Returns:
        Credentials as built by oauth2client.

    Raises:
        LoadDataPipelineException: An error with loading data has occurred.
    """

    if metadata_server.can_reach_metadata_server():
        # The GCE version of AppAssertionCredentials does not accept scopes
        # passed to it. Scopes for GCE credential are set at instance creation.
        return AppAssertionCredentials()

    try:
        credentials = ServiceAccountCredentials.from_json_keyfile_name(
            config.get('service_account_credentials_file'),
            scopes=REQUIRED_SCOPES)
    except (ValueError, KeyError) as e:
        raise LoadDataPipelineError(e)

    return credentials.create_delegated(
        config.get('domain_super_admin_email'))


def run(dao=None, cycle_timestamp=None, config=None, rate_limiter=None):
    """Runs the load GSuite account groups pipeline.

    Args:
        dao: Data access object.
        cycle_timestamp: String of timestamp, formatted as YYYYMMDDTHHMMSSZ.
        config: Dictionary of configurations.
        rate_limiter: RateLimiter object for the API client.

    Returns:
        None

    Raises:
        LoadDataPipelineException: An error with loading data has occurred.
    """
    if not _can_inventory_google_groups(config):
        raise LoadDataPipelineError(
            'Unable to inventory groups with specified arguments:\n%s', config)

    credentials = _build_proper_credentials(config)
    admin_client = AdminDirectoryClient(credentials=credentials,
                                        rate_limiter=rate_limiter)

    try:
        groups_map = admin_client.get_groups()
    except ApiExecutionError as e:
        raise LoadDataPipelineError(e)

    flattened_groups = transform_util.flatten_groups(groups_map)

    try:
        dao.load_data(RESOURCE_NAME, cycle_timestamp, flattened_groups)
    except (CSVFileError, MySQLError) as e:
        raise LoadDataPipelineError(e)
