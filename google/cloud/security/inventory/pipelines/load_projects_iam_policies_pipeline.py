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

"""Pipeline to load project IAM policies data into Inventory."""

import json

from google.cloud.security.common.data_access.errors import CSVFileError
from google.cloud.security.common.data_access.errors import MySQLError
from google.cloud.security.common.gcp_api._base_client import ApiExecutionError
# TODO: Investigate improving so the pylint disable isn't needed.
# pylint: disable=line-too-long
from google.cloud.security.common.gcp_api.cloud_resource_manager import CloudResourceManagerClient
from google.cloud.security.inventory import transform_util
from google.cloud.security.inventory.errors import LoadDataPipelineError


RESOURCE_NAME = 'project_iam_policies'
RAW_PROJECT_IAM_POLICIES = 'raw_project_iam_policies'

def run(dao=None, cycle_timestamp=None, configs=None, crm_rate_limiter=None):
    """Runs the load IAM policies data pipeline.

    Args:
        dao: Data access object.
        cycle_timestamp: String of timestamp, formatted as YYYYMMDDTHHMMSSZ.
        crm_rate_limiter: RateLimiter object for CRM API client.

    Returns:
        None

    Raises:
        LoadDataPipelineException: An error with loading data has occurred.
    """
    _ = configs

    # Get the projects for which we will retrieve the IAM policies.
    try:
        project_numbers = dao.select_project_numbers(RESOURCE_NAME,
                                                     cycle_timestamp)
    except MySQLError as e:
        raise LoadDataPipelineError(e)

    crm_client = CloudResourceManagerClient(rate_limiter=crm_rate_limiter)

    # Retrieve data from GCP.
    # Not using iterator since we will use the iam_policy_maps twice.
    iam_policy_maps = []
    for project_number in project_numbers:
        try:
            iam_policy_map = crm_client.get_project_iam_policies(
                RESOURCE_NAME, project_number)
            iam_policy_maps.append(iam_policy_map)
        except ApiExecutionError as e:
            LOGGER.error('Unable to get IAM policies for project %s:\n%s',
                         project_number, e)

    # Flatten and relationalize data for upload to cloud sql.
    flattened_iam_policies = (
        transform_util.flatten_iam_policies(iam_policy_maps))

    # Load flattened iam policies into cloud sql.
    # Load raw iam policies into cloud sql.
    # A separate table is used to store the raw iam policies because it is
    # much faster than updating these individually into the projects table.
    try:
        dao.load_data(RESOURCE_NAME, cycle_timestamp, flattened_iam_policies)

        for i in iam_policy_maps:
            i['iam_policy'] = json.dumps(i['iam_policy'])
        dao.load_data(RAW_PROJECT_IAM_POLICIES, cycle_timestamp,
                      iam_policy_maps)
    except (CSVFileError, MySQLError) as e:
        raise LoadDataPipelineError(e)
