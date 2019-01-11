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
"""Slack webhook notifier to perform notifications."""

import requests

from google.cloud.forseti.common.util import logger
from google.cloud.forseti.notifier.notifiers import base_notification

LOGGER = logger.get_logger(__name__)

TEMP_DIR = '/tmp'


class SlackWebhook(base_notification.BaseNotification):
    """Slack webhook notifier to perform notifications"""

    def _dump_slack_output(self, data, indent=0):
        """Iterate over a dictionary and output a custom formatted string

        Args:
            data (dict): a dictionary of violation data
            indent (int): number of spaces for indentation

        Returns:
            output: a string formatted violation
        """
        output = ''
        for key, value in sorted(data.items()):
            output += '\t' * indent + '*' + str(key) + '*:'
            if isinstance(value, dict):
                output += '\n' + self._dump_slack_output(value,
                                                         indent + 1) + '\n'
            else:
                if not value:
                    value = 'n/a'
                output += '\t' * (indent + 1) + '`' + str(value) + '`\n'

        return output

    def _compose(self, violation):
        """Composes the slack webhook content

        Args:
            violation (object): Violation to transform to ascii output.

        Returns:
            webhook_payload: a string formatted violation
        """

        return ('*type*:\t`{}`\n*details*:\n'.format(self.resource) +
                self._dump_slack_output(violation.get('violation_data'), 1))

    def _send(self, payload):
        """Sends a post to a Slack webhook url

        Args:
            payload (str): Payload data to send to slack.
        """
        url = self.notification_config.get('webhook_url')
        request = requests.post(url, json={'text': payload})

        LOGGER.info(request)

    def run(self):
        """Run the slack webhook notifier"""
        if not self.notification_config.get('webhook_url'):
            LOGGER.warn('No url found, not running Slack notifier.')
            return

        for violation in self.violations:
            webhook_payload = self._compose(violation=violation)
            self._send(payload=webhook_payload)
