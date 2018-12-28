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
"""Tests the email scanner summary notifier."""

import json
import mock
import unittest

from google.cloud.forseti.notifier.notifiers import slack_webhook
from tests.unittest_utils import ForsetiTestCase


class SlackWebhooknotifierTest(ForsetiTestCase):
    """Tests for the slack_webhook_notifier."""

    def test_can_compose_slack_message(self):
        """Test that the slack message is built correctly."""
        violation_data = """        
            {
                "role": "READER",
                "email": "",
                "bucket": "test-bucket-world-readable-123",
                "domain": "",
                "entity": "allUsers"
            }
        """

        violation = {'violation_data': json.loads(violation_data),
                     'resource_id': '123',
                     'rule_name': 'Public buckets (allUsers)',
                     'rule_index': 0L,
                     'violation_type': 'BUCKET_VIOLATION',
                     'id': 1L, 'resource_type': 'bucket'}

        with mock.patch.object(slack_webhook.SlackWebhook, '__init__', lambda x: None):
            slack_notifier = slack_webhook.SlackWebhook()
            slack_notifier.resource = 'buckets_acl_violations'
            actual_output = slack_notifier._compose(violation=violation)

            expected_output = "*type*:\t`buckets_acl_violations`\n*details*:\n\t*bucket*:\t\t`test-bucket-world-readable-123`\n\t*domain*:\t\t`n/a`\n\t*email*:\t\t`n/a`\n\t*entity*:\t\t`allUsers`\n\t*role*:\t\t`READER`"

            self.assertEqual(expected_output.strip(), actual_output.strip())

    def test_no_url_no_run_notifier(self):
        """Test that no url for Slack notifier will skip running."""
        with mock.patch.object(slack_webhook.SlackWebhook, '__init__', lambda x: None):
            slack_notifier = slack_webhook.SlackWebhook()
            slack_notifier.notification_config = {}
            slack_notifier._compose = mock.MagicMock()
            slack_notifier.run()

            slack_notifier._compose.assert_not_called()


if __name__ == '__main__':
    unittest.main()
