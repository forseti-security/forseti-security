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

"""Pipeline to load folder IAM policies data into Inventory."""

import json

from google.cloud.security.common.data_access import errors as da_errors
from google.cloud.security.common.gcp_api import errors as api_errors
from google.cloud.security.common.util import log_util
from google.cloud.security.common.util import parser
from google.cloud.security.inventory import errors as inventory_errors
from google.cloud.security.inventory.pipelines import base_pipeline


LOGGER = log_util.get_logger(__name__)


class LoadFolderIamPoliciesPipeline(base_pipeline.BasePipeline):
    """Pipeline to load folder IAM policies data into Inventory."""

    RESOURCE_NAME = 'folder_iam_policies'
    RAW_RESOURCE_NAME = 'raw_folder_iam_policies'

    def _transform(self, resource_from_api):
        """Yield an iterator of loadable iam policies.

        Args:
            resource_from_api (iterable): IAM policies as per-folder
                dictionary.
                Example: [{'folder_id': folder_id,
                          'iam_policy': policy}]

        Yields:
            iterable: IAM policies formatted for loading into database,
                as a per-folder dictionary.
        """
        for folder_policy_map in resource_from_api:
            iam_policy = folder_policy_map['iam_policy']
            bindings = iam_policy.get('bindings', [])
            for binding in bindings:
                members = binding.get('members', [])
                for member in members:
                    member_type, member_name, member_domain = (
                        parser.parse_member_info(member))
                    role = binding.get('role', '')
                    if role.startswith('roles/'):
                        role = role.replace('roles/', '')
                    yield {'folder_id': folder_policy_map['folder_id'],
                           'role': role,
                           'member_type': member_type,
                           'member_name': member_name,
                           'member_domain': member_domain}

    def _retrieve(self):
        """Retrieve the folder IAM policies from GCP.

        Returns:
            list: List of IAM policies as per-folder dictionary.
                Example: [{'folder_id': folder_id,
                           'iam_policy': iam_policy}]

        Raises:
            LoadDataPipelineException: An error with loading data has occurred.
        """
        try:
            folders = self.dao.get_folders(
                self.RESOURCE_NAME, self.cycle_timestamp)
        except da_errors.MySQLError as e:
            raise inventory_errors.LoadDataPipelineError(e)

        iam_policies = []
        for folder in folders:
            try:
                iam_policy = self.api_client.get_folder_iam_policies(
                    self.RESOURCE_NAME, folder.id)
                iam_policies.append(iam_policy)
            except api_errors.ApiExecutionError as e:
                LOGGER.error(
                    'Unable to get IAM policies for folder %s:\n%s',
                    folder.id, e)
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
