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

from google.cloud.forseti.common.util import date_time
from google.cloud.forseti.common.util import logger
from google.cloud.forseti.common.util import string_formats

LOGGER = logger.get_logger(__name__)


class InvalidDataFormatError(Exception):
    """Raised in case of an invalid notifier data format."""

    def __init__(self, notifier, invalid_data_format):
        """Constructor for the base notifier.

        Args:
            notifier (str): the notifier module/name
            invalid_data_format (str): the invalid data format in question.
        """
        super(InvalidDataFormatError, self).__init__(
            '%s: invalid data format: %s' % (notifier, invalid_data_format))


class BaseNotification(object):
    """Base notifier to perform notifications"""

    __metaclass__ = abc.ABCMeta
    supported_data_formats = ['csv', 'json']

    def __init__(self, resource, inventory_index_id,
                 violations, global_configs, notifier_config,
                 notification_config):

        """Constructor for the base notifier.

        Args:
            resource (str): Violation resource name.
            inventory_index_id (int64): Inventory index id.
            violations (dict): Violations.
            global_configs (dict): Global configurations.
            notifier_config (dict): Notifier configurations.
            notification_config (dict): notifier configurations.
        """
        self.inventory_index_id = inventory_index_id
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

    def _get_output_filename(self, filename_template):
        """Create the output filename.

        Args:
            filename_template (string): template to use for the output filename

        Returns:
            str: The output filename for the violations CSV file.
        """
        utc_now_datetime = date_time.get_utc_now_datetime()
        output_timestamp = utc_now_datetime.strftime(
            string_formats.TIMESTAMP_TIMEZONE_FILES)

        output_filename = filename_template.format(
            self.resource, str(self.inventory_index_id), output_timestamp)
        return output_filename

    @classmethod
    def check_data_format(cls, data_format):
        """Raise `InvalidDataFormatError` unless `data_format` is supported.

        Args:
            data_format (string): should be either 'csv' or 'json'

        Raises:
            InvalidDataFormatError: if not valid
        """
        if data_format not in cls.supported_data_formats:
            raise InvalidDataFormatError('Notifier', data_format)
