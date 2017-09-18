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

"""Pipeline to load GSuite Groups into Inventory."""

import json

from google.cloud.security.common.gcp_api import errors as api_errors
from google.cloud.security.common.util import log_util
from google.cloud.security.inventory import errors as inventory_errors
from google.cloud.security.inventory.pipelines import base_pipeline

LOGGER = log_util.get_logger(__name__)


class LoadGroupsPipeline(base_pipeline.BasePipeline):
    """Pipeline to load groups data into Inventory."""

    RESOURCE_NAME = 'groups'

    def _transform(self, resource_from_api):
        """Yield an iterator of loadable groups.

        Args:
            resource_from_api (list): Group objects from the Admin SDK.

        Yields:
            iterable: Loadable groups as a per-group dictionary.
        """
        for group in resource_from_api:
            yield {
                   'resource_key': group.get('email'),
                   'resource_type': 'GROUPS',
                   'resource_data': parser.json_stringify(group)
                   }

    def _retrieve(self):
        """Retrieve the groups from GSuite.

        Returns:
            list: Group list objects from the Admin SDK.

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
