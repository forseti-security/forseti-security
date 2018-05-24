# Copyright 2018 The Forseti Security Authors. All rights reserved.
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
"""Upload inventory summary to GCS."""

from googleapiclient.errors import HttpError

# pylint: disable=line-too-long
from google.cloud.forseti.common.util import date_time
from google.cloud.forseti.common.util import email
from google.cloud.forseti.common.util import errors as util_errors
from google.cloud.forseti.common.util import file_uploader
from google.cloud.forseti.common.util import logger
from google.cloud.forseti.common.util import string_formats
from google.cloud.forseti.notifier.notifiers.base_notification import BaseNotification
from google.cloud.forseti.services.inventory.storage import InventoryIndex
#pylint: enable=line-too-long

LOGGER = logger.get_logger(__name__)


class InventorySummary(object):
    """Create and send inventory summary."""

    def __init__(self, service_config, inventory_index_id):
        """Initialization.

        Args:
            inventory_index_id (int64): Inventory index id.
            service_config (ServiceConfig): Forseti 2.0 service configs.
        """
        self.service_config = service_config
        self.inventory_index_id = inventory_index_id

        self.notifier_config = self.service_config.get_notifier_config()

    def _get_output_filename(self, filename_template):
        """Create the output filename.

        Args:
            filename_template (string): template to use for the output filename

        Returns:
            str: The output filename for the inventory summary file.
        """
        utc_now_datetime = date_time.get_utc_now_datetime()
        output_timestamp = utc_now_datetime.strftime(
            string_formats.TIMESTAMP_TIMEZONE_FILES)

        return filename_template.format(str(self.inventory_index_id),
                                        output_timestamp)

    def _upload_to_gcs(self, summary_data):
        """Upload inventory summary to GCS.

        Args:
            summary_data (list): Summary of inventory data as a list of dicts.
                Example: [{resource_type, count}, {}, {}, ...]
        """
        LOGGER.debug('Uploading inventory summary data to GCS.')
        gcs_summary_config = (
            self.notifier_config.get('inventory').get('gcs_summary'))

        if not gcs_summary_config.get('gcs_path'):
            LOGGER.error('"gcs_path" not set for inventory summary notifier.')
            return

        if not gcs_summary_config['gcs_path'].startswith('gs://'):
            LOGGER.error('Invalid GCS path: %s', gcs_summary_config['gcs_path'])
            return

        data_format = gcs_summary_config.get('data_format', 'csv')
        BaseNotification.check_data_format(data_format)

        try:
            if data_format == 'csv':
                gcs_upload_path = '{}/{}'.format(
                    gcs_summary_config.get('gcs_path'),
                    self._get_output_filename(
                        string_formats.INVENTORY_SUMMARY_CSV_FMT))
                file_uploader.upload_csv(
                    'inv_summary', summary_data, gcs_upload_path)
            else:
                gcs_upload_path = '{}/{}'.format(
                    self.notifier_config['gcs_path'],
                    self._get_output_filename(
                        string_formats.INVENTORY_SUMMARY_JSON_FMT))
                file_uploader.upload_json(summary_data, gcs_upload_path)
        except HttpError as e:
            LOGGER.error('Unable to upload inventory summary in bucket %s:\n%s',
                         gcs_upload_path, e.content)

    def _send_email(self, summary_data):
        """Send the email for inventory summary.

        Args:
            summary_data (list): Summary of inventory data as a list of dicts.
                Example: [{resource_type, count}, {}, {}, ...]
        """
        LOGGER.debug('Sending inventory summary by email.')

        email_summary_config = (
            self.notifier_config.get('inventory').get('email_summary'))

        email_util = email.EmailUtil(
            email_summary_config.get('sendgrid_api_key'))

        email_subject = 'Inventory Summary: {0}'.format(
            self.inventory_index_id)

        email_content = email_util.render_from_template(
            'inventory_summary.jinja',
            {'inventory_index_id': self.inventory_index_id,
             'summary_data': summary_data})

        try:
            email_util.send(
                email_sender=email_summary_config.get('sender'),
                email_recipient=email_summary_config.get('recipient'),
                email_subject=email_subject,
                email_content=email_content,
                content_type='text/html')
            LOGGER.debug('Inventory summary sent successfully by email.')
        except util_errors.EmailSendError:
            LOGGER.error('Unable to send inventory summary email')

    def _get_summary_data(self):
        """Get the summarized inventory data.

        Returns:
            list: Summary of sorted inventory data as a list of dicts.
                Example: [{resource_type, count}, {}, {}, ...]

        Raises:
            NoDataError: If summary data is not found.
        """
        LOGGER.debug('Getting inventory summary data.')
        with self.service_config.scoped_session() as session:
            inventory_index = (
                session.query(InventoryIndex).get(self.inventory_index_id))

            summary = inventory_index.get_summary(session)
            if not summary:
                LOGGER.error('No inventory summary data found for inventory '
                             'index id: %s.', self.inventory_index_id)
                raise util_errors.NoDataError

            summary_data = []
            for key, value in summary.iteritems():
                summary_data.append(dict(resource_type=key, count=value))
            summary_data = (
                sorted(summary_data, key=lambda k: k['resource_type']))
            return summary_data

    def run(self):
        """Generate inventory summary."""
        LOGGER.info('Running inventory summary notifier.')

        inventory_notifier_config = self.notifier_config.get('inventory')
        if not inventory_notifier_config:
            LOGGER.info('No inventory configuration for notifier.')
            return

        try:
            is_gcs_summary_enabled = (
                inventory_notifier_config.get('gcs_summary').get('enabled'))
            is_email_summary_enabled = (
                inventory_notifier_config.get('email_summary').get('enabled'))
        except AttributeError as e:
            LOGGER.error(
                'Inventory summary can not be created because unable to get '
                'inventory summary configuration:\n%s', e)
            return

        if not is_gcs_summary_enabled and not is_email_summary_enabled:
            LOGGER.info('All inventory summaries are disabled.')
            return

        try:
            summary_data = self._get_summary_data()
        except util_errors.NoDataError:
            LOGGER.error('Inventory summary can not be created because '
                         'no summary data is found for index id: %s.',
                         self.inventory_index_id)
            return

        if is_gcs_summary_enabled:
            self._upload_to_gcs(summary_data)

        if is_email_summary_enabled:
            self._send_email(summary_data)

        LOGGER.info('Completed running inventory summary.')
