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
from google.cloud.security.inventory.pipelines import base_pipeline


# TODO: The next editor must remove this disable and correct issues.
# pylint: disable=missing-type-doc,missing-return-type-doc
# pylint: disable=missing-param-doc
# pylint: disable=missing-yield-type-doc


LOGGER = log_util.get_logger(__name__)


class LoadGroupsPipeline(base_pipeline.BasePipeline):
    """Pipeline to load groups data into Inventory."""

    RESOURCE_NAME = 'groups'

    def _transform(self, resource_from_api):
        """Yield an iterator of loadable groups.

        Args:
            A list of group objects from the Admin SDK.

        Yields:
            An iterable of loadable groups as a per-group dictionary.
        """
        for group in resource_from_api:
            yield {'group_id': group.get('id'),
                   'group_email': group.get('email'),
                   'group_kind': group.get('kind'),
                   'direct_member_count': group.get('directMembersCount'),
                   'raw_group': json.dumps(group)}

    def _retrieve(self):
        """Retrieve the groups from GSuite.

        Returns:
            A list of group list objects from the Admin SDK.

        Raises:
            LoadDataPipelineException: An error with loading data has occurred.
        """
        try:
            return self.api_client.get_groups()
        except api_errors.ApiExecutionError as e:
            raise inventory_errors.LoadDataPipelineError(e)


    def run(self):
        """Runs the load GSuite account groups pipeline."""
        groups_map = self._retrieve()

        if isinstance(groups_map, list):
            loadable_groups = self._transform(groups_map)
            self._load(self.RESOURCE_NAME, loadable_groups)
            self._get_loaded_count()
        else:
            LOGGER.warn('No groups retrieved.')
