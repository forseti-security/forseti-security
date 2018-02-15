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

from google.cloud.forseti.common.data_access import dao
from google.cloud.forseti.common.data_access import project_dao
from google.cloud.forseti.common.util import logger

LOGGER = logger.get_logger(__name__)


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

    @abc.abstractmethod
    def run(self):
        """Runs the pipeline."""
        pass
