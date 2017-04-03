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

# TODO: Investigate improving so the pylint disable isn't needed.
# pylint: disable=line-too-long
from google.cloud.security.common.data_access import errors as data_access_errors
from google.cloud.security.common.gcp_api import errors as api_errors
from google.cloud.security.inventory import errors as inventory_errors
from google.cloud.security.inventory.pipelines import base_pipeline
# pylint: enable=line-too-long


class LoadProjectsIamPoliciesPipeline(base_pipeline._BasePipeline):
    """Pipeline to load project IAM policies data into Inventory."""

    RESOURCE_NAME = 'project_iam_policies'
    RAW_RESOURCE_NAME = 'raw_project_iam_policies'

    def __init__(self, cycle_timestamp, configs, crm_client, dao, parser):
        """Constructor for the data pipeline.

        Args:
            cycle_timestamp: String of timestamp, formatted as YYYYMMDDTHHMMSSZ.
            configs: Dictionary of configurations.
            crm_client: CRM API client.
            dao: Data access object.
            parser: Forseti parser object.

        Returns:
            None
        """
        super(LoadProjectsIamPoliciesPipeline, self).__init__(
            self.RESOURCE_NAME, cycle_timestamp, configs, crm_client, dao)
        self.parser = parser


    def _load(self, iam_policy_maps, loadable_iam_policies):
        """ Load iam policies into cloud sql.

        A separate table is used to store the raw iam policies because it is
        much faster than updating these individually into the projects table.

        Args:
            iam_policy_maps: List of IAM policies as per-org dictionary.
                Example: {org_id: org_id,
                          iam_policy: iam_policy}
                https://cloud.google.com/resource-manager/reference/rest/Shared.Types/Policy
            loadable_iam_policies: An iterable of loadable iam policies,
                as a per-org dictionary.

        Returns:
            None
        """
        try:
            self.dao.load_data(self.name, self.cycle_timestamp,
                               loadable_iam_policies)

            for i in iam_policy_maps:
                i['iam_policy'] = json.dumps(i['iam_policy'])
            self.dao.load_data(self.RAW_RESOURCE_NAME, self.cycle_timestamp,
                               iam_policy_maps)
        except (data_access_errors.CSVFileError,
                data_access_errors.MySQLError) as e:
            raise inventory_errors.LoadDataPipelineError(e)


    def _transform(self, iam_policy_maps):
        """Yield an iterator of loadable iam policies.

        Args:
            iam_policy_maps: An iterable of iam policies as per-project
                dictionary.
                Example: {'project_number': 11111,
                          'iam_policy': policy}
                https://cloud.google.com/resource-manager/reference/rest/Shared.Types/Policy

        Yields:
            An iterable of loadable iam policies, as a per-org dictionary.
        """
        for iam_policy_map in iam_policy_maps:
            iam_policy = iam_policy_map['iam_policy']
            bindings = iam_policy.get('bindings', [])
            for binding in bindings:
                members = binding.get('members', [])
                for member in members:
                    member_type, member_name, member_domain = (
                        self.parser.parse_member_info(member))
                    role = binding.get('role', '')
                    if role.startswith('roles/'):
                        role = role.replace('roles/', '')
                        yield {
                            'project_number': iam_policy_map['project_number'],
                            'role': role,
                            'member_type': member_type,
                            'member_name': member_name,
                            'member_domain': member_domain}

    def _retrieve(self):
        """Retrieve the org IAM policies from GCP.

        Args:
            None

        Returns:
            iam_policy_maps: List of IAM policies as per-org dictionary.
                Example: [{project_number: project_number,
                          iam_policy: iam_policy}]
                https://cloud.google.com/resource-manager/reference/rest/Shared.Types/Policy
        """
        # Get the projects for which we will retrieve the IAM policies.
        try:
            project_numbers = self.dao.select_project_numbers(
                self.name, self.cycle_timestamp)
        except data_access_errors.MySQLError as e:
            raise inventory_errors.LoadDataPipelineError(e)
    
        # Retrieve data from GCP.
        # Not using iterator since we will use the iam_policy_maps twice.
        iam_policy_maps = []
        for project_number in project_numbers:
            try:
                iam_policy = self.api_client.get_project_iam_policies(
                    self.name, project_number)
                iam_policy_map = {'project_number': project_number,
                                  'iam_policy': iam_policy}
                iam_policy_maps.append(iam_policy_map)
            except api_errors.ApiExecutionError as e:
                self.logger.error(
                    'Unable to get IAM policies for project %s:\n%s',
                    project_number, e)
        return iam_policy_maps

    def run(self):
        """Runs the load IAM policies data pipeline.

        Args:
            None

        Returns:
            None

        Raises:
            LoadDataPipelineException: An error with loading data has occurred.
        """
        iam_policy_maps = self._retrieve()

        loadable_iam_policies = self._transform(iam_policy_maps)

        self._load(iam_policy_maps, loadable_iam_policies)

        self._get_loaded_count()
