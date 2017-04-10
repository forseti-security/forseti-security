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

"""Pipeline to load GSuite group members into Inventory."""

import json

from google.cloud.security.common.gcp_api import errors as api_errors
from google.cloud.security.common.data_access import errors as dao_errors
from google.cloud.security.inventory import errors as inventory_errors
from google.cloud.security.inventory import util
from google.cloud.security.inventory.pipelines import base_pipeline


class LoadGroupMembersPipeline(base_pipeline.BasePipeline):
    """Pipeline to load group members data into Inventory."""

    RESOURCE_NAME = 'group_members'

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
        super(LoadGroupMembersPipeline, self).__init__(
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

    def _fetch_groups_from_dao(self):
        """Fetch the latest group ids previously stored in Cloud SQL.

        Returns:
             A list of group ids.

        Raises:
            inventory_errors.LoadDataPipelineException: An error with loading
            data has occurred.
        """
        try:
            return self.dao.select_project_numbers(
                self.RESOURCE_NAME, self.cycle_timestamp)
        except dao_errors.MySQLError as e:
            raise inventory_errors.LoadDataPipelineError(e)


    def _transform(self, groups_members_map):
        """Yield an iterator of loadable groups.

        Args:
            groups_members_map: A tuple of (group_object, group_object_members)

        Yields:
            An iterable of loadable groups as a per-group dictionary.
        """
        for (group, group_member) in groups_members_map:
            for member in group_member:
                yield {'group_id': group,
                       'member_kind': member['kind'],
                       'member_role': member['role'],
                       'member_type': member['type'],
                       'member_status': member['status'],
                       'member_id': member['email'],
                       'raw_member': json.dumps(member)}

    def _retreive(self, group_ids):
        """Retrieve the membership for a given GSuite group.

        Returns:
            A list of tuples (group_id, group_members_data) from the Admin SDK.
        """
        group_members_map = []
        for group_id in group_ids:
            try:
                group_members_map.extend(
                    (group_id, self.api_client.get_group_members(group_id))
                )
            except api_errors.ApiExecutionError as e:
                raise inventory_errors.LoadDataPipelineError(e)

        return group_members_map

    def run(self):
        """Runs the load GSuite account groups pipeline."""
        if not util.can_inventory_groups(self.configs):
            raise inventory_errors.LoadDataPipelineError(
                'Unable to inventory groups with specified arguments:\n%s',
                self.configs)

        group_ids = self._fetch_groups_from_dao()

        groups_members_map = self._retrieve(group_ids)

        loadable_groups = self._transform(groups_members_map)

        self._load(self.RESOURCE_NAME, loadable_groups)

        self._get_loaded_count()
