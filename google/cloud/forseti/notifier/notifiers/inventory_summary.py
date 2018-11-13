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
# pylint: enable=line-too-long

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
            LOGGER.error('gcs_path not set for inventory summary notifier.')
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
                    gcs_summary_config.get('gcs_path'),
                    self._get_output_filename(
                        string_formats.INVENTORY_SUMMARY_JSON_FMT))
                file_uploader.upload_json(summary_data, gcs_upload_path)
        except HttpError:
            LOGGER.exception('Unable to upload inventory summary in bucket %s:',
                             gcs_upload_path)

    def _send_email(self, summary_data, details_data):
        """Send the email for inventory summary.

        Args:
            summary_data (list): Summary of inventory data as a list of dicts.
                Example: [{resource_type, count}, {}, {}, ...]

            details_data (list): Details of inventory data as a list of dicts.
                Example: [[{resource_type, count}, {}, {}, ...]
        """
        LOGGER.debug('Sending inventory summary by email.')

        email_summary_config = (
            self.notifier_config.get('inventory').get('email_summary'))

        email_util = email.EmailUtil(
            email_summary_config.get('sendgrid_api_key'))

        email_subject = 'Inventory Summary: {0}'.format(
            self.inventory_index_id)

        inventory_index_datetime = (
            date_time.get_date_from_microtimestamp(self.inventory_index_id))

        timestamp = inventory_index_datetime.strftime(
            string_formats.DEFAULT_FORSETI_TIMESTAMP)

        gsuite_dwd_status = self._get_gsuite_dwd_status(summary_data)

        email_content = email_util.render_from_template(
            'inventory_summary.jinja',
            {'inventory_index_id': self.inventory_index_id,
             'timestamp': timestamp,
             'gsuite_dwd_status': gsuite_dwd_status,
             'summary_data': summary_data,
             'details_data': details_data})

        try:
            email_util.send(
                email_sender=email_summary_config.get('sender'),
                email_recipient=email_summary_config.get('recipient'),
                email_subject=email_subject,
                email_content=email_content,
                content_type='text/html')
            LOGGER.debug('Inventory summary sent successfully by email.')
        except util_errors.EmailSendError:
            LOGGER.exception('Unable to send inventory summary email')

    @staticmethod
    def transform_to_template(data):
        """Helper method to return sorted list of dicts.

        Args:
            data (dict): dictionary of resource_type: count pairs.

        Returns:
            list: Sorted data as a list of dicts.
                Example: [{resource_type, count}, {}, {}, ...]
        """
        template_data = []
        for key, value in data.iteritems():
            template_data.append(dict(resource_type=key, count=value))
        return sorted(template_data, key=lambda k: k['resource_type'])

    @staticmethod
    def _get_gsuite_dwd_status(summary_data):
        """Get the status of whether G Suite DwD is enabled or not.

        Args:
            summary_data (list): Summary of inventory data as a list of dicts.
                Example: [{resource_type, count}, {}, {}, ...]

        Returns:
            str: disabled or enabled.
        """
        gsuite_types = set(['gsuite_user'])
        summary_data_keys = set()
        if summary_data is None:
            return 'disabled'

        for resource in summary_data:
            summary_data_keys.add(resource['resource_type'])

        if gsuite_types.issubset(summary_data_keys):
            return 'enabled'
        return 'disabled'

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

            summary_data = self.transform_to_template(summary)
            return summary_data

    def _get_details_data(self):
        """Get the detailed summarized inventory data.

        Returns:
            list: Summary details of sorted inventory data as a list of dicts.
                Example: [{resource_type, count}, {}, {}, ...]

        Raises:
            NoDataError: If summary details data is not found.
        """
        LOGGER.debug('Getting inventory summary details data.')
        with self.service_config.scoped_session() as session:
            inventory_index = (
                session.query(InventoryIndex).get(self.inventory_index_id))

            details = inventory_index.get_details(session)
            if not details:
                LOGGER.error('No inventory summary detail data found for '
                             'inventory index id: %s.', self.inventory_index_id)
                raise util_errors.NoDataError

            details_data = self.transform_to_template(details)
            return details_data

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
        except AttributeError:
            LOGGER.exception(
                'Inventory summary can not be created because unable to get '
                'inventory summary configuration.')
            return

        if not is_gcs_summary_enabled and not is_email_summary_enabled:
            LOGGER.info('All inventory summaries are disabled.')
            return

        try:
            summary_data = self._get_summary_data()
            details_data = self._get_details_data()
        except util_errors.NoDataError:
            LOGGER.exception('Inventory summary can not be created because '
                             'no summary data is found for index id: %s.',
                             self.inventory_index_id)
            return

        if is_gcs_summary_enabled:
            summary_and_details_data = sorted((summary_data + details_data),
                                              key=lambda k: k['resource_type'])
            self._upload_to_gcs(summary_and_details_data)

        if is_email_summary_enabled:
            self._send_email(summary_data, details_data)

        LOGGER.info('Completed running inventory summary.')
