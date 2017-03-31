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

"""Pipeline to load org IAM policies data into Inventory."""

import json

from google.cloud.security.common.data_access.errors import CSVFileError
from google.cloud.security.common.data_access.errors import MySQLError
from google.cloud.security.common.gcp_api import cloud_resource_manager as crm
from google.cloud.security.common.gcp_api._base_client import ApiExecutionError
from google.cloud.security.inventory import transform_util
from google.cloud.security.inventory.errors import LoadDataPipelineError

RESOURCE_NAME = 'org_iam_policies'
RAW_ORG_IAM_POLICIES = 'raw_org_iam_policies'


def run(dao=None, cycle_timestamp=None, configs=None, crm_rate_limiter=None):
    """Runs the load IAM policies data pipeline.

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
    org_id = configs.get('organization_id')
    # Check if the placeholder is replaced in the config/flag.
    if org_id == '<organization id>':
        raise LoadDataPipelineError('No organization id is specified.')

    crm_client = crm.CloudResourceManagerClient(rate_limiter=crm_rate_limiter)
    try:
        # Retrieve data from GCP.
        # Flatten the iterator since we will use it twice, and it is faster
        # than cloning to 2 iterators.
        iam_policies_map = crm_client.get_org_iam_policies(
            RESOURCE_NAME, org_id)
        # TODO: Investigate improving so the pylint disable isn't needed.
        # pylint: disable=redefined-variable-type
        iam_policies_map = list(iam_policies_map)

        # Flatten and relationalize data for upload to cloud sql.
        flattened_iam_policies = (
            transform_util.flatten_iam_policies(iam_policies_map))
    except ApiExecutionError as e:
        raise LoadDataPipelineError(e)

    # Load flattened iam policies into cloud sql.
    # Load raw iam policies into cloud sql.
    # A separate table is used to store the raw iam policies because it is
    # much faster than updating these individually into the projects table.
    try:
        dao.load_data(RESOURCE_NAME, cycle_timestamp, flattened_iam_policies)

        for i in iam_policies_map:
            i['iam_policy'] = json.dumps(i['iam_policy'])
        dao.load_data(RAW_ORG_IAM_POLICIES, cycle_timestamp, iam_policies_map)
    except (CSVFileError, MySQLError) as e:
        raise LoadDataPipelineError(e)
