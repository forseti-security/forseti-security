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

from google.cloud.security.common.gcp_api import errors as api_errors
from google.cloud.security.inventory import errors as inventory_errors
from google.cloud.security.inventory.pipelines import base_pipeline


class LoadOrgIamPoliciesPipeline(base_pipeline.BasePipeline):
    """Pipeline to load org IAM policies data into Inventory."""

    RESOURCE_NAME = 'org_iam_policies'
    RAW_RESOURCE_NAME = 'raw_org_iam_policies'

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
        super(LoadOrgIamPoliciesPipeline, self).__init__(
            self.RESOURCE_NAME, cycle_timestamp, configs, crm_client, dao)
        self.parser = parser

    def _transform(self, iam_policies_map):
        """Yield an iterator of loadable iam policies.

        Args:
            iam_policies_map: An iterable of iam policies as per-project
                dictionary.
                Example: {'project_number': 11111,
                          'iam_policy': policy}
                https://cloud.google.com/resource-manager/reference/rest/Shared.Types/Policy

        Yields:
            An iterable of loadable iam policies, as a per-org dictionary.
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

    def _retrieve(self):
        """Retrieve the org IAM policies from GCP.

        Args:
            None

        Returns:
            iam_policies_map: List of IAM policies as per-org dictionary.
                Example: {org_id: org_id,
                          iam_policy: iam_policy}
                https://cloud.google.com/resource-manager/reference/rest/Shared.Types/Policy

        Raises:
            LoadDataPipelineException: An error with loading data has occurred.
        """
        try:
            # Flatten the iterator since we will use it twice, and it is faster
            # than cloning to 2 iterators.
            return list(self.api_client.get_org_iam_policies(
                self.name, self.configs.get('organization_id')))
        except api_errors.ApiExecutionError as e:
            raise inventory_errors.LoadDataPipelineError(e)

    def run(self):
        """Runs the data pipeline.

        Args:
            None

        Returns:
            None
        """
        org_id = self.configs.get('organization_id')
        # Check if the placeholder is replaced in the config/flag.
        if org_id == '<organization id>':
            raise inventory_errors.LoadDataPipelineError(
                'No organization id is specified.')

        iam_policies_map = self._retrieve()

        loadable_iam_policies = self._transform(iam_policies_map)

        self._load(self.name, loadable_iam_policies)

        # A separate table is used to store the raw iam policies json
        # because it is much faster than updating these individually
        # into the orgs table.
        for i in iam_policies_map:
            i['iam_policy'] = json.dumps(i['iam_policy'])
        self._load(self.RAW_RESOURCE_NAME, iam_policies_map)

        self._get_loaded_count()
