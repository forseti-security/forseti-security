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

"""Pipeline to load folders data into Inventory."""

import json

from dateutil import parser as dateutil_parser

from google.cloud.security.common.gcp_type import resource_util
from google.cloud.security.common.util import log_util
from google.cloud.security.inventory.pipelines import base_pipeline

# TODO: The next editor must remove this disable and correct issues.
# pylint: disable=missing-type-doc,missing-return-type-doc
# pylint: disable=missing-yield-type-doc

LOGGER = log_util.get_logger(__name__)


class LoadFoldersPipeline(base_pipeline.BasePipeline):
    """Pipeline to load folder data into Inventory."""

    RESOURCE_NAME = 'folders'

    MYSQL_DATETIME_FORMAT = '%Y-%m-%d %H:%M:%S'

    def _transform(self, resource_from_api):
        """Yield an iterator of loadable folders.

        Args:
            resource_from_api: An list of resource manager folders.

        Yields:
            An iterable of loadable folders, each folder as a dict.
        """
        for folder in resource_from_api:
            folder_json = json.dumps(folder)
            try:
                parsed_time = dateutil_parser.parse(folder.get('createTime'))
                create_time_fmt = (
                    parsed_time.strftime(self.MYSQL_DATETIME_FORMAT))
            except (TypeError, ValueError) as e:
                LOGGER.error(
                    'Unable to parse createTime from folder: %s\n%s',
                    folder.get('createTime', ''), e)
                create_time_fmt = '0000-00-00 00:00:00'

            # folder_name is the unique identifier for the folder,
            # formatted as "folders/<folder_id>".
            folder_name = folder.get('name')
            folder_id = folder_name[len('%s/' % self.RESOURCE_NAME):]
            parent_type, parent_id = None, None
            if folder.get('parent'):
                parent_type, parent_id = folder.get('parent', '').split('/')
                parent_type = resource_util.type_from_name(parent_type)

            yield {'folder_id': folder_id,
                   'name': folder_name,
                   'display_name': folder.get('displayName'),
                   'lifecycle_state': folder.get('lifecycleState'),
                   'parent_type': parent_type,
                   'parent_id': parent_id,
                   'raw_folder': folder_json,
                   'create_time': create_time_fmt}

    def _retrieve(self):
        """Retrieve the folder resources from GCP.

        Returns:
            An iterable of resource manager folder search response.
        """
        return self.safe_api_call('get_folders', self.RESOURCE_NAME)

    def run(self):
        """Runs the data pipeline."""
        folders_map = self._retrieve()
        if folders_map:
            loadable_folders = self._transform(folders_map)
            self._load(self.RESOURCE_NAME, loadable_folders)
            self._get_loaded_count()
