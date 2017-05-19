
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

"""Internal pipeline to perform notifications"""

# TODO: Investigate improving so we can avoid the pylint disable.
# pylint: disable=line-too-long,no-name-in-module
from google.cloud.security.common.util import log_util
from google.cloud.security.common.util.email_util import EmailUtil
from google.cloud.security.notifier.pipelines import notification_pipeline
# pylint: enable=line-too-long,no-name-in-module

LOGGER = log_util.get_logger(__name__)


class EmailPipeline(notification_pipeline.NotificationPipeline):
    """Email pipeline to perform notifications"""

    def _send_email(self):
        """Send a summary email of the scan."""

        mail_util = EmailUtil(self.pipeline_config['sendgrid_api_key'])

        # Render the email template with values.
        scan_date = self.cycle_timestamp
        email_content = EmailUtil.render_from_template(
            'scanner_summary.jinja', {
                'scan_date':  self.cycle_timestamp,
                'resource_summaries': {}, #TODO
                'violation_errors': self.violations,
            })

        # Create an attachment out of the csv file and base64 encode the content.
        """
        attachment = EmailUtil.create_attachment(
            file_location=csv_name,
            content_type='text/csv',
            filename=_get_output_filename(now_utc),
            disposition='attachment',
            content_id='Scanner Violations'
        )
        """
        mail_util.send(email_sender=self.pipeline_config['sender'],
                       email_recipient=self.pipeline_config['recipient'],
                       email_subject='Forseti Violations {0}'.format(scan_date),
                       email_content=email_content,
                       content_type='text/html')

    def run(self):
        self._send_email()
