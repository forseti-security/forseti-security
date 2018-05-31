# Copyright 2017 The Forseti Security Authors. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Forseti installer server config object."""

from config import Config


class ServerConfig(Config):
    """Forseti installer server config object."""

    # pylint: disable=too-many-instance-attributes

    def __init__(self, **kwargs):
        """Initialize.

        Args:
            kwargs (dict): The kwargs.
        """
        super(ServerConfig, self).__init__(**kwargs)
        self.installation_type = 'server'
        self.cloudsql_instance = None
        self.cloudsql_region = kwargs.get('cloudsql_region')

        # forseti_conf_server.yaml.in properties
        self.sendgrid_api_key = kwargs.get('sendgrid_api_key')
        self.notification_sender_email = None
        self.notification_recipient_email = (
            kwargs.get('notification_recipient_email'))
        self.gsuite_superadmin_email = kwargs.get('gsuite_superadmin_email')
        self.skip_sendgrid_config = bool(kwargs.get('skip_sendgrid_config'))

    def generate_cloudsql_instance(self):
        """Update cloudsql_instance when the identifier is generated."""
        self.cloudsql_instance = '{}-{}-db-{}'.format('forseti',
                                                      self.installation_type,
                                                      self.identifier)
