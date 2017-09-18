# Copyright 2017 The Forseti Security Authors. All rights reserved.
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

from google.cloud.security.common.data_access import errors as dao_errors
from google.cloud.security.common.util import log_util
from google.cloud.security.common.util import parser
from google.cloud.security.inventory import errors as inventory_errors
from google.cloud.security.inventory.pipelines import base_pipeline

LOGGER = log_util.get_logger(__name__)


class LoadProjectsIamPoliciesPipeline(base_pipeline.BasePipeline):
    """Pipeline to load project IAM policies data into Inventory."""

    RESOURCE_NAME = 'project_iam_policies'
    RAW_RESOURCE_NAME = 'raw_project_iam_policies'

    def _transform(self, resource_from_api):
        """Yield an iterator of loadable iam policies.

        Args:
            resource_from_api (iterable): IAM policies as per-project
                dictionary.
                Example: {'project_number': 11111,
                          'iam_policy': policy}
                https://cloud.google.com/resource-manager/reference/rest/Shared.Types/Policy

        Yields:
            iterable: Loadable iam policies, as a per-org dictionary.
        """
        for iam_policy_map in resource_from_api:
            iam_policy = iam_policy_map['iam_policy']
            bindings = iam_policy.get('bindings', [])
            for binding in bindings:
                members = binding.get('members', [])
                for member in members:
                    member_type, member_name, member_domain = (
                        parser.parse_member_info(member))
                    role = binding.get('role', '')
                    if role.startswith('roles/'):
                        role = role.replace('roles/', '')
                        yield {
                            'resource_key': iam_policy_map['project_number'],
                            'resource_type': 'PROJECTS_IAM_POLICIES',
                            'resource_data': parser.json_stringify({'project_number': iam_policy_map['project_number'],
                                'role': role,
                                'member_type': member_type,
                                'member_name': member_name,
                                'member_domain': member_domain})
                            }

    def _retrieve(self):
        """Retrieve the project IAM policies from GCP.

        Returns:
            list: IAM policies as per-org dictionary.
                Example: [{project_number: project_number,
                          iam_policy: iam_policy}]
                https://cloud.google.com/resource-manager/reference/rest/Shared.Types/Policy

        Raises:
            LoadDataPipelineException: An error with loading data has occurred.
        """
        # Get the projects for which we will retrieve the IAM policies.
        try:
            project_numbers = self.dao.get_project_numbers(
                self.RESOURCE_NAME, self.cycle_timestamp)
        except dao_errors.MySQLError as e:
            raise inventory_errors.LoadDataPipelineError(e)

        # Retrieve data from GCP.
        # Not using iterator since we will use the iam_policy_maps twice.
        iam_policy_maps = []
        for project_number in project_numbers:
            iam_policy = self.safe_api_call('get_project_iam_policies',
                                            self.RESOURCE_NAME,
                                            project_number)
            if iam_policy:
                iam_policy_map = {'project_number': project_number,
                                  'iam_policy': iam_policy}
                iam_policy_maps.append(iam_policy_map)
        return iam_policy_maps

    def run(self):
        """Runs the load IAM policies data pipeline."""
        iam_policy_maps = self._retrieve()

        loadable_iam_policies = self._transform(iam_policy_maps)

        self._load(self.RESOURCE_NAME, loadable_iam_policies)

        # A separate table is used to store the raw iam policies json
        # because it is much faster than updating these individually
        # into the projects table.
        for i in iam_policy_maps:
            i['iam_policy'] = json.dumps(i['iam_policy'])
        self._load(self.RAW_RESOURCE_NAME, iam_policy_maps)

        self._get_loaded_count()
