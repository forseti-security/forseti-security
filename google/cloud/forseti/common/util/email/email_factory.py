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

"""Base email connector to select connector"""

from google.cloud.forseti.notifier.notifiers import email_violations
from google.cloud.forseti.common.util.email import sendgrid_connector
from google.cloud.forseti.services.base import config
from google.cloud.forseti.common.util import logger

LOGGER = logger.get_logger(__name__)

EMAIL_CONNECTOR_FACTORY = {
    'sendgrid': sendgrid_connector
}


class EmailFactory(object):
    """Email Factory to select connector."""

    def __init__(self, notifier_config, notification_config):
        """Constructor for the email factory.

        Args:
            notifier_config (dict): Notifier configurations.
            notification_config (dict): notifier configurations.
        """
        self.notification_config = notification_config
        self.notifier_config = notifier_config
        self.email_connector_config = notifier_config.get('email_connector_config')

    def get_connector(self):
        """Gets the connector and executes it."""
        try:
            connector_name = self.email_connector_config('name')
            auth = self.email_connector_config.get('auth')
            sender = self.email_connector_config.get('sender')
            recipient = self.email_connector_config.get('recipient')
            return EMAIL_CONNECTOR_FACTORY[connector_name](sender, recipient, auth)
        except:
            LOGGER.error('Connector details not found')
