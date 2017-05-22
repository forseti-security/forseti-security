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
# pylint: disable=line-too-long,no-name-in-module
from google.cloud.security.common.data_access import dao
from google.cloud.security.common.data_access import project_dao
from google.cloud.security.common.data_access import violation_dao
from google.cloud.security.common.util import log_util
# pylint: enable=line-too-long,no-name-in-module

LOGGER = log_util.get_logger(__name__)


class BaseNotificationPipeline(object):
    """Base pipeline to perform notifications"""

    def __init__(self, resource, cycle_timestamp,
                 violations, notifier_config, pipeline_config):
        """Constructor for the base pipeline.

        Args:
            cycle_timestamp: String of timestamp, formatted as YYYYMMDDTHHMMSSZ.
            configs: Dictionary of configurations.

        Returns:
            None
        """
        self.cycle_timestamp = cycle_timestamp
        self.resource = resource
        self.notifier_config = notifier_config
        self.pipeline_config = pipeline_config
        # TODO: import api_client
        # self.api_client = api_client

        # Initializing DAOs
        self.dao = dao.Dao()
        self.project_dao = project_dao.ProjectDao()
        self.violation_dao = violation_dao.ViolationDao()

        # Get violations
        self.violations = violations

    def _get_violations(self, timestamp):
        """Get all violtions.

        Args:
            timestamp: String of timestamp, formatted as YYYYMMDDTHHMMSSZ.

        Returns:
            Dictonary of violations organized per resource type
        """
        violations = {
            'violations': self.violation_dao.get_all_violations(
                timestamp, 'violations'),
            'bucket_acl_violations': self.violation_dao.get_all_violations(
                timestamp, 'buckets_acl_violations')
        }

        return violations

    @abc.abstractmethod
    def run(self):
        """Runs the pipeline."""
        pass
