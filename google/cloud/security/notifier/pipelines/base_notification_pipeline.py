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

"""Base pipeline to perform notifications"""

import abc

from google.cloud.security.common.data_access import dao
from google.cloud.security.common.data_access import project_dao
from google.cloud.security.common.data_access import violation_dao
from google.cloud.security.common.util import log_util

LOGGER = log_util.get_logger(__name__)


# pylint: disable=too-many-instance-attributes
class BaseNotificationPipeline(object):
    """Base pipeline to perform notifications"""

    __metaclass__ = abc.ABCMeta

    def __init__(self, resource, cycle_timestamp,
                 violations, global_configs, notifier_config, pipeline_config):
        """Constructor for the base pipeline.

        Args:
            resource (str): Violation resource name.
            cycle_timestamp (str): Snapshot timestamp,
               formatted as YYYYMMDDTHHMMSSZ.
            violations (dict): Violations.
            global_configs (dict): Global configurations.
            notifier_config (dict): Notifier configurations.
            pipeline_config (dict): Pipeline configurations.
        """
        self.cycle_timestamp = cycle_timestamp
        self.resource = resource
        self.global_configs = global_configs
        self.notifier_config = notifier_config
        self.pipeline_config = pipeline_config
        # TODO: import api_client
        # self.api_client = api_client

        # Initializing DAOs
        self.dao = None
        self.project_dao = None
        self.violation_dao = None

        # Get violations
        self.violations = violations

    def _get_dao(self):
        """Init or get dao.

        Returns:
            dao: Dao instance
        """
        if not self.dao:
            self.dao = dao.Dao(self.global_configs)
        return self.dao

    def _get_project_dao(self):
        """Init or get project_dao.

        Returns:
            project_dao: ProjectDao instance
        """
        if not self.project_dao:
            self.project_dao = project_dao.ProjectDao(self.global_configs)
        return self.project_dao

    def _get_violation_dao(self):
        """Init or get violation dao.

        Returns:
            violation_dao: ViolationDao instance
        """
        if not self.violation_dao:
            self.violation_dao = violation_dao.ViolationDao(self.global_configs)
        return self.violation_dao

    def _get_violations(self, timestamp):
        """Get all violtions.

        Args:
            timestamp (str): String of timestamp, formatted as YYYYMMDDTHHMMSSZ.

        Returns:
            dict: Violations organized per resource type.
        """
        vdao = self._get_violation_dao()
        violations = {
            'violations': vdao.get_all_violations(
                timestamp, 'violations'),
            'bucket_acl_violations': vdao.get_all_violations(
                timestamp, 'buckets_acl_violations')
        }

        return violations

    def _check_send_only_new(self, **kwargs):
        """Checks to send only new violations.

         Args:
            **kwargs: Arbitrary keyword arguments.

        Returns:
            boolean: whether true or not
        """
        violation = kwargs.get('violation')

        if self.pipeline_config.get('send_only_new', False):
            return violation.get('new_violation')

        return True

    def _filter_only_new(self, violations):
        """Filters only new violations (if applicable).

        Args:
            violations (list): List of violations

        Returns:
            violations (list): filtered violations
        """
        filtered_violations = []

        if self.pipeline_config.get('send_only_new', False):
            for violation in violations:
                if violation.get('new_violation'):
                    filtered_violations.append(violation)

            return filtered_violations

        return violations

    @abc.abstractmethod
    def run(self):
        """Runs the pipeline."""
        pass
