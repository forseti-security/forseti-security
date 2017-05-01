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

"""Pipeline to load GSuite Group members into Inventory."""

import json

from google.cloud.security.common.gcp_api import errors as api_errors
from google.cloud.security.common.util import log_util
from google.cloud.security.common.data_access import errors as dao_errors
from google.cloud.security.inventory import errors as inventory_errors
from google.cloud.security.inventory.pipelines import base_pipeline


LOGGER = log_util.get_logger(__name__)


class LoadGroupMembersPipeline(base_pipeline.BasePipeline):
    """Pipeline to load group members data into Inventory."""

    RESOURCE_NAME = 'group_members'
    GROUP_CHUNK_SIZE = 20


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

    def _fetch_groups_from_dao(self):
        """Fetch the latest group ids previously stored in Cloud SQL.

        Returns:
             A list of group ids.

        Raises:
            inventory_errors.LoadDataPipelineException: An error with loading
            data has occurred.
        """
        try:
            group_ids = self.dao.select_group_ids(
                self.RESOURCE_NAME, self.cycle_timestamp)
        except dao_errors.MySQLError as e:
            raise inventory_errors.LoadDataPipelineError(e)

        return group_ids


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
                       'member_kind': member.get('kind'),
                       'member_role': member.get('role'),
                       'member_type': member.get('type'),
                       'member_status': member.get('status'),
                       'member_id': member.get('id'),
                       'member_email': member.get('email'),
                       'raw_member': json.dumps(member)}

    def _retrieve(self, group_ids):  # pylint: disable=arguments-differ
        """Retrieve the membership for a list of given GSuite groups.

        Returns:
            A list of tuples (group_id, group_members) from the Admin SDK, e.g.
            (string, [])
        """

        group_members_map = []

        for group_id in group_ids:
            try:
                group_members = self.api_client.get_group_members(group_id)
            except api_errors.ApiExecutionError as e:
                raise inventory_errors.LoadDataPipelineError(e)

            group_members_map.append((group_id, group_members))
            LOGGER.debug('Retrieved members from %s: %d',
                         group_id,
                         len(group_members))

        return group_members_map

    def run(self):
        """Runs the load GSuite account groups pipeline."""

        group_ids = self._fetch_groups_from_dao()

        def chunker(seq, size):
            """Helper to chunk a list.

            Args:
                seq: A list.
                size: Integer of the desired chunk size.

            Returns:
                A tuple of the chunked seq.
            """
            return (seq[pos:pos + size] for pos in xrange(0, len(seq), size))

        # TODO: keep track of group_ids that are not retrieved/committed to db
        chunk_counter = 0
        for group_ids_in_chunk in chunker(group_ids, self.GROUP_CHUNK_SIZE):
            LOGGER.debug('Retrieving a batch of group members in %s chunks.\n'
                         'Current chunk count is: %s',
                         self.GROUP_CHUNK_SIZE, chunk_counter)
            groups_members_map = self._retrieve(group_ids_in_chunk)

            if isinstance(groups_members_map, list):
                loadable_group_members = self._transform(groups_members_map)
                self._load(self.RESOURCE_NAME, loadable_group_members)
                self._get_loaded_count()
            else:
                LOGGER.warn('No group members retrieved.')
            chunk_counter += 1
