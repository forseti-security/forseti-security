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

"""Base notifier to perform notifications"""

import abc

from google.cloud.forseti.common.util import logger

LOGGER = logger.get_logger(__name__)


class BaseNotification(object):
    """Base notifier to perform notifications"""

    __metaclass__ = abc.ABCMeta

    def __init__(self, resource, cycle_timestamp,
                 violations, global_configs, notifier_config,
                 notification_config):
        """Constructor for the base notifier.

        Args:
            resource (str): Violation resource name.
            cycle_timestamp (str): Snapshot timestamp,
               formatted as YYYYMMDDTHHMMSSZ.
            violations (dict): Violations.
            global_configs (dict): Global configurations.
            notifier_config (dict): Notifier configurations.
            notification_config (dict): notifier configurations.
        """
        self.cycle_timestamp = cycle_timestamp
        self.resource = resource
        self.global_configs = global_configs
        self.notifier_config = notifier_config
        self.notification_config = notification_config
        # TODO: import api_client
        # self.api_client = api_client

        # Get violations
        self.violations = violations

    @abc.abstractmethod
    def run(self):
        """Runs the notifier."""
        pass
