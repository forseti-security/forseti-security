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

"""Pipeline to load GSuite Account Groups into Inventory."""

import json

from google.cloud.security.common.gcp_api import errors as api_errors
from google.cloud.security.inventory import errors as inventory_errors
from google.cloud.security.inventory.pipelines import base_pipeline


class LoadGroupsPipeline(base_pipeline.BasePipeline):
    """Pipeline to load groups data into Inventory."""

    RESOURCE_NAME = 'groups'

    def __init__(self, cycle_timestamp, configs, admin_client, dao):
        """Constructor for the data pipeline.

        Args:
            cycle_timestamp: String of timestamp, formatted as YYYYMMDDTHHMMSSZ.
            configs: Dictionary of configurations.
            admin_client: Admin API client.
            dao: Data access object.

        Returns:
            None
        """
        super(LoadGroupsPipeline, self).__init__(
            cycle_timestamp, configs, admin_client, dao)

    def _can_inventory_google_groups(self):
        """A simple function that validates required inputs to inventory groups.

        Returns:
            Boolean
        """
        required_execution_config_flags = [
            self.configs.get('domain_super_admin_email'),
            self.configs.get('groups_service_account_key_file')]

        return all(required_execution_config_flags)

    def _transform(self, groups_members_map):
        """Yield an iterator of loadable groups.

        Args:
            groups_members_map: A tuple of (group_object, group_object_members)

        Yields:
            An iterable of loadable groups as a per-group dictionary.
        """
        for (group, members) in groups_members_map:
            print group
            for member in members:
                print member
                yield {'group_id': group['id'],
                       'group_email': group['email'],
                       'group_kind': group['kind'],
                       'member_kind': member['kind'],
                       'member_role': member['role'],
                       'member_type': member['type'],
                       'member_status': member['status'],
                       'member_id': member['email'],
                       'raw_group': json.dumps((group, members))}

    def _retrieve(self):
        """Retrieve the groups from GSuite.

        Returns:
            A list of group objects returned from the API.

        Raises:
            LoadDataPipelineException: An error with loading data has occurred.
        """
        results = []
        try:
            groups = self.api_client.get_groups()
            for group in groups:
                results.append((group, self.api_client.get_members(group)))
        except api_errors.ApiExecutionError as e:
            raise inventory_errors.LoadDataPipelineError(e)

        return results

    def run(self):
        """Runs the load GSuite account groups pipeline."""
        if not self._can_inventory_google_groups():
            raise inventory_errors.LoadDataPipelineError(
                'Unable to inventory groups with specified arguments:\n%s',
                self.configs)

        groups_map = self._retrieve()

        loadable_groups = self._transform(groups_map)

        self._load(self.RESOURCE_NAME, loadable_groups)

        self._get_loaded_count()
