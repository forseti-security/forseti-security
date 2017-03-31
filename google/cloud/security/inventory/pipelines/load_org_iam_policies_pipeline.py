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

# TODO: Investigate improving so the pylint disable isn't needed.
# pylint: disable=line-too-long
from google.cloud.security.common.data_access import errors as data_access_errors
from google.cloud.security.common.gcp_api import errors as api_errors
from google.cloud.security.inventory import errors as inventory_errors
from google.cloud.security.inventory.pipelines import base_pipeline
# pylint: enable=line-too-long


class LoadOrgIamPoliciesPipeline(base_pipeline._BasePipeline):
    """Pipeline to load org IAM policies data into Inventory."""

    RAW_ORG_IAM_POLICIES = 'raw_org_iam_policies'

    def __init__(self, cycle_timestamp, configs, crm_client, dao, parser):
        """Constructor for the data pipeline.

        Args:
            cycle_timestamp: String of timestamp, formatted as YYYYMMDDTHHMMSSZ.
            configs: Dictionary of configurations.
            crm_client: CRM API client.
            dao: Data access object.
            parser: Forseti parser utility object.

        Returns:
            None
        """
        super(LoadOrgIamPoliciesPipeline, self).__init__(
            'org_iam_policies', cycle_timestamp, configs, crm_client, dao)
        self.parser = parser

    def _load(self, iam_policies_map, flattened_iam_policies):
        """ Load iam policies into cloud sql.

        A separate table is used to store the raw iam policies because it is
        much faster than updating these individually into the projects table.
        
        Args:
            iam_policies_map: List of IAM policies as per-org dictionary.
                Example: {org_id: org_id,
                          iam_policy: iam_policy}
                https://cloud.google.com/resource-manager/reference/rest/Shared.Types/Policy
            flattened_iam_policies: An iterable of flattened iam policies,
                as a per-org dictionary.

        Returns:
            None
        """
        try:
            self.dao.load_data(self.name, self.cycle_timestamp,
                               flattened_iam_policies)

            for i in iam_policies_map:
                i['iam_policy'] = json.dumps(i['iam_policy'])
            self.dao.load_data(self.RAW_ORG_IAM_POLICIES, self.cycle_timestamp,
                               iam_policies_map)

        except (data_access_errors.CSVFileError,
                data_access_errors.MySQLError) as e:
            raise inventory_errors.LoadDataPipelineError(e)

    def _flatten(self, iam_policies_map):
        """Yield an iterator of flattened iam policies.
    
        Args:
            iam_policies_map: An iterable of iam policies as per-project dictionary.
                Example: {'project_number': 11111,
                          'iam_policy': policy}
                https://cloud.google.com/resource-manager/reference/rest/Shared.Types/Policy
    
        Yields:
            An iterable of flattened iam policies, as a per-org dictionary.
        """
        for iam_policy_map in iam_policies_map:
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
                    yield {'org_id': iam_policy_map['org_id'],
                           'role': role,
                           'member_type': member_type,
                           'member_name': member_name,
                           'member_domain': member_domain}

    def _retrieve(self, org_id):
        """Retrieve the org IAM policies from GCP.

        Args:
            org_id: String of the organization id

        Returns:
            iam_policies_map: List of IAM policies as per-org dictionary.
                Example: {org_id: org_id,
                          iam_policy: iam_policy}
                https://cloud.google.com/resource-manager/reference/rest/Shared.Types/Policy
        """
        try:
            # Retrieve data from GCP.
            # Flatten the iterator since we will use it twice, and it is faster
            # than cloning to 2 iterators.
            return list(self.gcp_api_client.get_org_iam_policies(
                self.name, org_id))
        except api_errors.ApiExecutionError as e:
            raise inventory_errors.LoadDataPipelineError(e)

    def run(self):
        """Runs the data pipeline."""
        org_id = self.configs.get('organization_id')
        # Check if the placeholder is replaced in the config/flag.
        if org_id == '<organization id>':
            raise inventory_errors.LoadDataPipelineError(
                'No organization id is specified.')

        iam_policies_map = self._retrieve(org_id)

        flattened_iam_policies = self._flatten(iam_policies_map)

        self._load(iam_policies_map, flattened_iam_policies)

        self._get_loaded_count()
