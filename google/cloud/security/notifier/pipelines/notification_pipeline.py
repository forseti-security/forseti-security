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

"""Base pipeline to perform notifications"""

import abc

# TODO: Investigate improving so we can avoid the pylint disable.
# pylint: disable=line-too-long
from google.cloud.security.common.data_access import errors as data_access_errors
from google.cloud.security.common.data_access import dao
from google.cloud.security.common.data_access import project_dao
from google.cloud.security.common.data_access import violation_dao
from google.cloud.security.common.util import log_util
from google.cloud.security.common.data_access import errors as db_errors
from google.cloud.security.inventory import errors as inventory_errors
# pylint: enable=line-too-long

LOGGER = log_util.get_logger(__name__)


class NotificationPipeline(object):
    """Base pipeline to perform notifications"""

    def __init__(self, cycle_timestamp, configs):
        """Constructor for the base pipeline.

        Args:
            cycle_timestamp: String of timestamp, formatted as YYYYMMDDTHHMMSSZ.
            configs: Dictionary of configurations.
            api_client: API client object.

        Returns:
            None
        """
        self.cycle_timestamp = cycle_timestamp
        self.configs = configs
        #self.api_client = api_client

        # Initializing DAOs
        self.dao = dao.Dao()
        self.project_dao = project_dao.ProjectDao()
        self.violation_dao = violation_dao.ViolationDao()

        # Get violations
        self.violations = self._get_violations(cycle_timestamp)

    def _get_violations(self, timestamp=None):
        if not timestamp:
            timestamp = _get_timestamp()

        v = {
            'violations': self.violation_dao.get_all_violations(
                            timestamp,
                            'violations'),
            'bucket_acl_violations': self.violation_dao.get_all_violations(
                            timestamp,
                            'buckets_acl_violations')
        }

        return v

    @abc.abstractmethod
    def run(self):
        """Runs the pipeline."""
        pass
