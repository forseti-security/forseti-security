
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

"""Email pipeline to notify that inventory snapshots have been completed."""

# TODO: Investigate improving so we can avoid the pylint disable.
# pylint: disable=line-too-long,no-name-in-module
from google.cloud.security.common.util import errors as util_errors
from google.cloud.security.common.util import log_util
from google.cloud.security.common.util.email_util import EmailUtil
from google.cloud.security.notifier.pipelines import base_notification_pipeline as bnp
# pylint: enable=line-too-long,no-name-in-module


LOGGER = log_util.get_logger(__name__)


class EmailInventorySnapshopSummaryPipeline(bnp.BaseNotificationPipeline):
    """Email pipeline for inventory snapshot summary"""

    def __init__(self, sendgrid_key):
        self.email_util = EmailUtil(sendgrid_key)

    def _compose(self, snapshot_time, snapshot_timestamp, status,
                 inventory_pipelines):
        """Compose the email content.

        Args:
            snapshot_time: Datetime object of the cycle, in UTC.
            snapshot_timestamp: String of timestamp,
                formatted as YYYYMMDDTHHMMSSZ.
            status: String of the overall status of current snapshot cycle.
            inventory_pipelines: List of inventory pipelines.
    
        Returns:
            email_subject: String of the email subject.
            email_content: String of template content rendered with
                the provided variables.
        """
        email_subject = 'Inventory Snapshot Complete: {0} {1}'.format(
            snapshot_timestamp, status)
    
        email_content = EmailUtil.render_from_template(
            'inventory_snapshot_summary.jinja',
            {'snapshot_time':
                 snapshot_time.strftime('%Y %b %d, %H:%M:%S (UTC)'),
             'snapshot_timestamp': snapshot_timestamp,
             'status_summary': status,
             'pipelines': inventory_pipelines})

        return email_subject, email_content

    def _send(self, email_sender, email_recipient,
              email_subject, email_content, attachment=None):
        """Send a summary email of the scan.

        Args:
            email_sender: String of the sender of the email.
            email_recipient: String of the recipient of the email.
            email_subject: String of the email subject.
            email_content: String of template content rendered with
                the provided variables.
        """
        try:
            self.email_util.send(email_sender=email_sender,
                                 email_recipient=email_recipient,
                                 email_subject=email_subject,
                                 email_content=email_content,
                                 content_type='text/html',
                                 attachment=attachment)
        except util_errors.EmailSendError:
            LOGGER.error('Unable to send email that inventory snapshot '
                         'completed.')

    def run(self, snapshot_time, snapshot_timestamp, status,
            inventory_pipelines, email_sender, email_recipient):
        """Run the email pipeline
    
        Args:
            snapshot_time: Datetime object of the cycle, in UTC.
            snapshot_timestamp: String of timestamp, formatted
                as YYYYMMDDTHHMMSSZ.
            status: String of the overall status of current snapshot cycle.
            inventory_pipelines: List of inventory pipelines.
            email_sender: String of the sender of the email.
            email_recipient: String of the recipient of the email.
    
        Returns:
             None
        """
        
        email_subject, email_content = self._compose(
            snapshot_time, snapshot_timestamp, status, inventory_pipelines)

        self._send(email_sender, email_recipient, email_subject, email_content)
