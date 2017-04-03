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

from google.cloud.security.common.data_access import errors as data_errors
from google.cloud.security.common.gcp_api import errors as api_errors
from google.cloud.security.common.util import metadata_server
from google.cloud.security.inventory import errors as inventory_errors
from google.cloud.security.inventory.pipelines import base_pipeline


class LoadGroupsPipeline(base_pipeline.BasePipeline):
    """Pipeline to load groups data into Inventory."""
    # TODO: Add unit tests.

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
            self.RESOURCE_NAME, cycle_timestamp, configs, admin_client, dao)

    def _is_our_environment_gce(self):
        """A simple function that returns a boolean if we're running in GCE."""
        return metadata_server.can_reach_metadata_server()

    def _can_inventory_google_groups(self):
        """A simple function that validates required inputs to inventory groups.

        Args:
            None

        Returns:
            Boolean
        """
        required_gcp_execution_config = [
            self.configs.get('service_account_email'),
            self.configs.get('domain_super_admin_email')]

        required_local_execution_config = [
            self.configs.get('service_account_email'),
            self.configs.get('service_account_credentials_file'),
            self.configs.get('domain_super_admin_email')]

        if self._is_our_environment_gce():
            required_execution_config = required_gcp_execution_config
        else:
            required_execution_config = required_local_execution_config

        return all(required_execution_config)

    def _load(self, loadable_groups):
        """ Load groups into cloud sql.

        Args:
            groups_map: An iterable of Admin SDK Directory API Groups.
            https://google-api-client-libraries.appspot.com/documentation/admin/directory_v1/python/latest/admin_directory_v1.groups.html#list

        Returns:
            None
        """
        try:
            self.dao.load_data(self.name, self.cycle_timestamp, loadable_groups)
        except (data_errors.CSVFileError, data_errors.MySQLError) as e:
            raise inventory_errors.LoadDataPipelineError(e)

    def _transform(self, groups_map):
        """Yield an iterator of loadable groups.
        Args:
            groups_map: An iterable of Admin SDK Directory API Groups.
            https://google-api-client-libraries.appspot.com/documentation/admin/directory_v1/python/latest/admin_directory_v1.groups.html#list

        Yields:
            An iterable of loadable groups as a per-group dictionary.
        """
        for group in groups_map:
            yield {'group_id': group.get('id'),
                   'group_email': group.get('email')}

    def _retrieve(self):
        """Retrieve the org IAM policies from GCP.

        Args:
            None

        Returns:
            A list of group objects returned from the API.
        """
        try:
            return self.api_client.get_groups()
        except api_errors.ApiExecutionError as e:
            raise inventory_errors.LoadDataPipelineError(e)

    def run(self):
        """Runs the load GSuite account groups pipeline.

        Args:
            dao: Data access object.
            cycle_timestamp: String of timestamp, formatted as YYYYMMDDTHHMMSSZ.
            config: Dictionary of configurations.
            rate_limiter: RateLimiter object for the API client.

        Returns:
            None

        Raises:
            LoadDataPipelineException: An error with loading data has occurred.
        """
        if not self._can_inventory_google_groups():
            raise inventory_errors.LoadDataPipelineError(
                'Unable to inventory groups with specified arguments:\n%s',
                self.configs)

        groups_map = self._retrieve()

        loadable_groups = self._transform(groups_map)

        self._load(loadable_groups)

        self._get_loaded_count()
