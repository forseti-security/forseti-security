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

from google.cloud.forseti.common.util import logger

LOGGER = logger.get_logger(__name__)


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
        self.global_configs = global_configs
        self.notifier_config = notifier_config
        self.pipeline_config = pipeline_config
        # TODO: import api_client
        # self.api_client = api_client

        # Get violations
        self.violations = dict()
        self.violations[resource] = violations

    def add_data(self, resource, violations):
        """Add violation data for another resource type.

        Args:
            resource (str): Violation resource name.
            violations (dict): Violations.
        """
        if resource in self.violations:
            raise ValueError('resource %s specified more than once' % resource)
        self.violations[resource] = violations

    @abc.abstractmethod
    def run(self):
        """Runs the pipeline."""
        pass
