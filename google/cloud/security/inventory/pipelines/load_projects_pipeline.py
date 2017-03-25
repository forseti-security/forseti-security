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

"""Pipeline to load projects data into Inventory."""

from google.cloud.security.common.data_access.errors import CSVFileError
from google.cloud.security.common.data_access.errors import MySQLError
from google.cloud.security.common.gcp_api._base_client import ApiExecutionError
# TODO: Investigate improving so the pylint disable isn't needed.
# pylint: disable=line-too-long
from google.cloud.security.common.gcp_api.cloud_resource_manager import CloudResourceManagerClient
from google.cloud.security.common.gcp_type.resource import LifecycleState
from google.cloud.security.common.util import log_util
from google.cloud.security.inventory import transform_util
from google.cloud.security.inventory.errors import LoadDataPipelineError


LOGGER = log_util.get_logger(__name__)

RESOURCE_NAME = 'projects'


def run(dao=None, cycle_timestamp=None, configs=None, crm_rate_limiter=None):
    """Runs the load projects data pipeline.

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

    # Retrieve data from GCP.
    crm_client = CloudResourceManagerClient(rate_limiter=crm_rate_limiter)
    try:
        projects = crm_client.get_projects(RESOURCE_NAME,
                                           configs['organization_id'],
                                           lifecycleState=LifecycleState.ACTIVE)
        # Flatten and relationalize data for upload to cloud sql.
        flattened_projects = transform_util.flatten_projects(projects)
    except ApiExecutionError as e:
        raise LoadDataPipelineError(e)

    # Load projects data into cloud sql.
    try:
        dao.load_data(RESOURCE_NAME, cycle_timestamp, flattened_projects)
    except (CSVFileError, MySQLError) as e:
        raise LoadDataPipelineError(e)
