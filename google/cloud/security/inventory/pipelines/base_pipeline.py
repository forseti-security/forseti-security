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

"""Base pipeline to load data into inventory."""

import abc

from google.cloud.security.common.data_access import errors as dao_errors
from google.cloud.security.common.gcp_api import errors as api_errors
from google.cloud.security.common.util import log_util
from google.cloud.security.inventory import errors as inventory_errors

LOGGER = log_util.get_logger(__name__)


class BasePipeline(object):
    """Base client for a specified GCP API and credentials."""

    __metaclass__ = abc.ABCMeta

    RESOURCE_NAME = None

    MYSQL_DATETIME_FORMAT = '%Y-%m-%d %H:%M:%S'

    def __init__(self, cycle_timestamp, global_configs, api_client, dao):
        """Constructor for the base pipeline.

        Args:
            cycle_timestamp (str): Timestamp, formatted as YYYYMMDDTHHMMSSZ.
            global_configs (dict): Global configurations.
            api_client (API): Forseti API client object.
            dao (dao): Forseti data access object.
        """
        self.cycle_timestamp = cycle_timestamp
        self.global_configs = global_configs
        self.api_client = api_client
        self.dao = dao
        self.count = None

    @abc.abstractmethod
    def run(self):
        """Runs the pipeline."""
        # TODO: should this raise an error?
        pass

    @abc.abstractmethod
    def _retrieve(self):
        """Retrieve resource data from source."""
        pass

    @abc.abstractmethod
    def _transform(self, resource_from_api):
        """Transform api resource data into loadable format.

        Args:
            resource_from_api (dict): Resources from API responses.
        """
        pass

    def safe_api_call(self, method_name, *args, **kwargs):
        """Safely fetch resources from an API client.

        ApiNotEnabledError and ApiExecutionError are logged and return None.

        Args:
            method_name (str): The method to call on the API client.
            *args (list): Args to pass to the method.
            **kwargs (dict): Key word args to pass to the method.

        Returns:
            object: The dict or list response from the API client method.
        """
        try:
            method = getattr(self.api_client, method_name)
            return method(*args, **kwargs)
        except api_errors.ApiNotEnabledError as e:
            LOGGER.warn('Api not enabled on target project: %s.', e)
            return None
        except api_errors.ApiExecutionError as e:
            LOGGER.error(
                'Error calling API, may have incomplete results: %s.', e)
            return None

    @staticmethod
    def _to_bool(value):
        """Transforms a value into a database boolean (or None).

        Args:
            value (anything): Value to be transformed.

        Returns:
            int or None: database boolean
        """
        # pylint: disable=no-else-return
        if value is None:
            return None
        elif value:
            return 1
        else:
            return 0

    @staticmethod
    def _to_int(value):
        """Transforms a value into a database integer (or None).

        Args:
            value (anything): Value to be transformed.

        Returns:
            int or None: database integer
        """
        # pylint: disable=no-else-return
        # TODO: Investigate adding a try around this and simplifying.
        if value is None:
            return None
        elif not value:
            return 0
        else:
            return int(value)

    def _load(self, resource_name, data):
        """ Loads data into Forseti storage.

        Args:
            resource_name (str): Resource name.
            data (iterable or list): Data to be uploaded.

        Raises:
            LoadDataPipelineError: An error with loading data has occurred.
        """
        if not data:
            LOGGER.warn('No %s data to load into Cloud SQL, continuing...',
                        resource_name)
            return

        try:
            print("1!!!!!!!!!!!!!!!!!!!")
            print(resource_name)
            print(data)
            print("~~~~~~~~~~~~~~~~~~~~~~~~~")
            self.dao.load_data(resource_name, self.cycle_timestamp, data)
        except (dao_errors.CSVFileError,
                dao_errors.MySQLError) as e:
            raise inventory_errors.LoadDataPipelineError(e)

    def _get_loaded_count(self):
        """Get the count of how many of a resource has been loaded."""
        try:
            self.count = self.dao.select_record_count(
                self.RESOURCE_NAME,
                self.cycle_timestamp)
        except dao_errors.MySQLError as e:
            LOGGER.error('Unable to retrieve record count for %s_%s:\n%s',
                         self.RESOURCE_NAME, self.cycle_timestamp, e)
