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

"""Slack webhook pipeline to perform notifications."""
import json
import requests

# TODO: Investigate improving so we can avoid the pylint disable.
# pylint: disable=line-too-long
from google.cloud.security.common.util import log_util
from google.cloud.security.notifier.pipelines import base_notification_pipeline as bnp
# pylint: enable=line-too-long


LOGGER = log_util.get_logger(__name__)

TEMP_DIR = '/tmp'
VIOLATIONS_JSON_FMT = 'violations.{}.{}.{}.json'
OUTPUT_TIMESTAMP_FMT = '%Y%m%dT%H%M%SZ'


class SlackWebhookPipeline(bnp.BaseNotificationPipeline):
    """Slack webhook pipeline to perform notifications"""

    def _dump_slack_output(self, data, indent=0):
        """Iterate over a dictionary and output a custom formatted string

        Args:
            data (dict): a dictionary of violation data
            indent (int): number of spaces for indentation

        Returns:
            output: a string formatted violation
        """
        output = ''
        for key, value in data.iteritems():
            output += '\t' * indent + '*' + str(key) + '*:'
            if isinstance(value, dict):
                output += '\n' + self._dump_slack_output(value,
                                                         indent + 1) + '\n'
            else:
                if not value:
                    value = 'n/a'
                output += '\t' * (indent + 1) + '`' + str(value) + '`\n'

        return output

    def _compose(self, **kwargs):
        """Composes the slack webhook content

        Args:
            **kwargs: Arbitrary keyword arguments.

        Returns:
            webhook_payload: a string formatted violation
        """

        violation = kwargs.get('violation')

        payload = {
            'type': self.resource,
            'details': json.loads(violation.get('violation_data'))
        }

        return self._dump_slack_output(payload)

    def _send(self, **kwargs):
        """Sends a post to a Slack webhook url

        Args:
            **kwargs: Arbitrary keyword arguments.
                payload: violation data for body of POST request\
        """
        url = self.pipeline_config.get('webhook_url')
        request = requests.post(url, json={'text': kwargs.get('payload')})

        LOGGER.info(request)

    def run(self):
        """Run the slack webhook pipeline"""
        for violation in self.violations:
            webhook_payload = self._compose(violation=violation)
            self._send(payload=webhook_payload)
