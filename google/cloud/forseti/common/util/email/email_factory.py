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

"""Email Factory to select connector"""

from google.cloud.forseti.common.util import logger
from google.cloud.forseti.common.util.email import sendgrid_connector
from google.cloud.forseti.common.util.errors import InvalidInputError


LOGGER = logger.get_logger(__name__)

EMAIL_CONNECTOR_FACTORY = {
    'sendgrid': sendgrid_connector.SendgridConnector
}


class EmailFactory(object):
    """Email Factory to select connector"""

    def __init__(self, notifier_config):
        """Constructor for the email factory.

        Args:
            notifier_config (dict): Notifier configurations.
        """
        self.notifier_config = notifier_config
        self.email_connector_config = (self.notifier_config
                                       .get('email_connector'))

    def get_connector(self):
        """Gets the connector and executes it.

        Returns:
            object: Connector class

        Raises:
            InvalidInputError: Raised if invalid input is encountered.
        """
        if not self.notifier_config:
            LOGGER.exception('Notifier config is missing')
            raise InvalidInputError(self.notifier_config)

        if self.email_connector_config:
            connector_name = self.email_connector_config.get('name')
            auth = self.email_connector_config.get('auth')
            sender = self.email_connector_config.get('sender')
            recipient = self.email_connector_config.get('recipient')
        # else block below is added for backward compatibility.
        else:
            connector_name = 'sendgrid'
            auth = self.notifier_config
            sender = self.notifier_config.get('sender')
            recipient = self.notifier_config.get('recipient')

        try:
            connector = EMAIL_CONNECTOR_FACTORY[connector_name]
        except KeyError:
            LOGGER.exception('Specified connector not found: %s',
                             connector_name)
            raise InvalidInputError(self.notifier_config)

        try:
            return connector(sender, recipient, auth)
        except Exception:
            LOGGER.exception('Error occurred to instantiate connector.')
            raise InvalidInputError(self.notifier_config)
