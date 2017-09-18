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

"""Pipeline to load org IAM policies data into Inventory."""

import json

from google.cloud.security.common.data_access import errors as da_errors
from google.cloud.security.common.util import log_util
from google.cloud.security.common.util import parser
from google.cloud.security.inventory import errors as inventory_errors
from google.cloud.security.inventory.pipelines import base_pipeline

LOGGER = log_util.get_logger(__name__)


class LoadOrgIamPoliciesPipeline(base_pipeline.BasePipeline):
    """Pipeline to load org IAM policies data into Inventory."""

    RESOURCE_NAME = 'org_iam_policies'
    RAW_RESOURCE_NAME = 'raw_org_iam_policies'

    def _transform(self, resource_from_api):
        """Yield an iterator of loadable iam policies.

        Args:
            resource_from_api (iterable): IAM policies as per-org
                dictionary.
                Example: [{'org_id': '11111',
                          'iam_policy': policy}]
                https://cloud.google.com/resource-manager/reference/rest/Shared.Types/Policy

        Yields:
            iterable: Loadable iam policies, as a per-org dictionary.
        """
        for org_policy_map in resource_from_api:
            iam_policy = org_policy_map['iam_policy']
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
                            'resource_key': org_policy_map['org_id'],
                            'resource_type': 'ORG_IAM_POLICY',
                            'resource_data': {
                            'org_id': org_policy_map['org_id'],
                           'role': role,
                           'member_type': member_type,
                           'member_name': member_name,
                           'member_domain': member_domain}
                           }

    def _retrieve(self):
        """Retrieve the org IAM policies from GCP.

        Returns:
            list: IAM policies as per-org dictionary.
                Example: [{'org_id': org_id,
                           'iam_policy': iam_policy}]
                https://cloud.google.com/resource-manager/reference/rest/Shared.Types/Policy

        Raises:
            LoadDataPipelineException: An error with loading data has occurred.
        """
        try:
            orgs = self.dao.get_organizations(
                self.RESOURCE_NAME, self.cycle_timestamp)
        except da_errors.MySQLError as e:
            raise inventory_errors.LoadDataPipelineError(e)

        iam_policies = []
        for org in orgs:
            iam_policy = self.safe_api_call('get_org_iam_policies',
                                            self.RESOURCE_NAME,
                                            org.id)
            if iam_policy:
                iam_policies.append(iam_policy)
        return iam_policies

    def run(self):
        """Runs the data pipeline."""
        iam_policies = self._retrieve()

        loadable_iam_policies = self._transform(iam_policies)

        self._load(self.RESOURCE_NAME, loadable_iam_policies)

        for i in iam_policies:
            i['iam_policy'] = json.dumps(i['iam_policy'])
        self._load(self.RAW_RESOURCE_NAME, iam_policies)

        self._get_loaded_count()
