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

from google.cloud.security.common.data_access import errors as data_errors
from google.cloud.security.common.gcp_api import cloud_resource_manager as crm
from google.cloud.security.common.gcp_api import errors as api_errors
from google.cloud.security.common.gcp_type import resource
from google.cloud.security.common.util.log_util import LogUtil
from google.cloud.security.inventory import errors as inventory_errors
from google.cloud.security.inventory import transform_util


LOGGER = LogUtil.setup_logging(__name__)

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
    crm_client = crm.CloudResourceManagerClient(rate_limiter=crm_rate_limiter)
    try:
        projects = crm_client.get_projects(
            RESOURCE_NAME,
            configs['organization_id'],
            lifecycleState=resource.LifecycleState.ACTIVE)
        # Flatten and relationalize data for upload to cloud sql.
        flattened_projects = transform_util.flatten_projects(projects)
    except api_errors.ApiExecutionError as e:
        raise inventory_errors.LoadDataPipelineError(e)

    # Load projects data into cloud sql.
    try:
        dao.load_data(RESOURCE_NAME, cycle_timestamp, flattened_projects)
    except (data_errors.CSVFileError, data_errors.MySQLError) as e:
        raise inventory_errors.LoadDataPipelineError(e)
