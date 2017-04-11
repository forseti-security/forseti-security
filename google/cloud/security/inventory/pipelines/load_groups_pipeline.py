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

"""Pipeline to load GSuite Groups into Inventory."""

import json

from google.cloud.security.common.gcp_api import errors as api_errors
from google.cloud.security.common.util import log_util
from google.cloud.security.inventory import errors as inventory_errors
from google.cloud.security.inventory import util
from google.cloud.security.inventory.pipelines import base_pipeline


LOGGER = log_util.get_logger(__name__)


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

    def _transform(self, groups_map):
        """Yield an iterator of loadable groups.

        Args:
            A list of group objects from the Admin SDK.

        Yields:
            An iterable of loadable groups as a per-group dictionary.
        """
        for group in groups_map:
            yield {'group_id': group['id'],
                   'group_email': group['email'],
                   'group_kind': group['kind'],
                   'direct_member_count': group['directMembersCount'],
                   'raw_group': json.dumps(group)}

    def _retrieve(self):
        """Retrieve the groups from GSuite.

        Returns:
            A list of group list objects from the Admin SDK.

        Raises:
            LoadDataPipelineException: An error with loading data has occurred.
        """
        groups = []
        try:
            groups.extend(self.api_client.get_groups())
        except api_errors.ApiExecutionError as e:
            raise inventory_errors.LoadDataPipelineError(e)


    def run(self):
        """Runs the load GSuite account groups pipeline."""
        if not util.can_inventory_groups(self.configs):
            raise inventory_errors.LoadDataPipelineError(
                'Unable to inventory groups with specified arguments:\n%s',
                self.configs)

        groups_map = self._retrieve()

        if isinstance(groups_map, list):
            loadable_groups = self._transform(groups_map)
            self._load(self.RESOURCE_NAME, loadable_groups)
            self._get_loaded_count()
        else:
            LOGGER.warn('No groups retrieved.')
