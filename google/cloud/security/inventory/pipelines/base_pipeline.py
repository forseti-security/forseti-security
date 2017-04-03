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

"""Base pipeline to load data into inventory."""

import abc

# TODO: Investigate improving so we can avoid the pylint disable.
# pylint: disable=line-too-long
from google.cloud.security.common.data_access import errors as data_access_errors
from google.cloud.security.common.util.log_util import LogUtil
# pylint: enable=line-too-long


class BasePipeline(object):
    """Base client for a specified GCP API and credentials."""

    __metaclass__ = abc.ABCMeta

    def __init__(self, name, cycle_timestamp, configs, api_client, dao):
        """Constructor for the base pipeline.

        Args:
            name: String of the resource loaded by the pipeline.
            cycle_timestamp: String of timestamp, formatted as YYYYMMDDTHHMMSSZ.
            configs: Dictionary of configurations.
            api_client: API client object.
            dao: Data access object.

        Returns:
            None
        """
        self.logger = LogUtil.setup_logging(__name__)
        self.name = name
        self.cycle_timestamp = cycle_timestamp
        self.configs = configs
        self.api_client = api_client
        self.dao = dao
        self.count = None

    @abc.abstractmethod
    def run(self):
        """Runs the pipeline."""
        pass

    @abc.abstractmethod
    def _retrieve(self):
        """Retrieve resource data from source."""
        pass

    @abc.abstractmethod
    def _transform(self, resource_from_api):
        """Transform api resource data into loadable format."""
        pass

    @abc.abstractmethod
    def _load(self):
        """Load data into Cloud SQL."""
        pass

    def _get_loaded_count(self):
        """Get the count of how many of a resource has been loaded."""
        try:
            self.count = self.dao.select_record_count(
                self.name,
                self.cycle_timestamp)
        except data_access_errors.MySQLError as e:
            self.logger.error('Unable to retrieve record count for %s_%s:\n%s',
                              self.name, self.cycle_timestamp, e)
