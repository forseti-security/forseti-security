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

from builtins import str
import time
import requests

from google.cloud.forseti.common.util import logger
from google.cloud.forseti.notifier.notifiers import base_notification

LOGGER = logger.get_logger(__name__)

TEMP_DIR = '/tmp'

DEFAULT_RETRIES = 2
# 'Retry-After' (seconds) is not always set in the header of the response
# received from Slack API. Hence, setting the default wait to 30 seconds based
# on Slack rate limits documentation.
# https://api.slack.com/docs/rate-limits
DEFAULT_WAIT = 30


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

        if not isinstance(data, dict):
            LOGGER.debug('Violation data is not a dictionary type. '
                         f'Violation data: {data}')
            return '\t' * (indent + 1) + '`' + str(data) + '`\n'

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
        for retry_number in range(DEFAULT_RETRIES):
            url = self.notification_config.get('webhook_url')
            response = requests.post(url, json={'text': payload})
            if response.status_code == 200:
                LOGGER.info('Post was successfully sent to Slack webhook: %s',
                            response)
                break
            elif response.status_code == 429:
                LOGGER.debug('HTTP 429 Too many requests error encountered')
                # Wait for 30 seconds before retrying.
                time.sleep(DEFAULT_WAIT)
                continue
            # Retry before raising exception for all errors.
            elif retry_number == DEFAULT_RETRIES - 1:
                response.raise_for_status()

    def run(self):
        """Run the slack webhook notifier"""
        if not self.notification_config.get('webhook_url'):
            LOGGER.warning('No url found, not running Slack notifier.')
            return

        for violation in self.violations:
            webhook_payload = self._compose(violation=violation)
            try:
                self._send(payload=webhook_payload)
            except Exception:  # pylint: disable=broad-except
                LOGGER.exception('Post was not sent to Slack webhook.')
