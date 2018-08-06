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
"""Mock Configs."""


from google.cloud.forseti.services.base.config import AbstractInventoryConfig
from google.cloud.forseti.services.base.config import AbstractServiceConfig


class InventoryConfig(AbstractInventoryConfig):
    """Implements composed dependency injection for the inventory."""

    def __init__(self,
                 organization_id,
                 gsuite_sa_path,
                 gsuite_admin_email,
                 record_file=None,
                 replay_file=None,
                 *args,
                 **kwargs):

        super(InventoryConfig, self).__init__(*args, **kwargs)

    def get_root_resource_id(self):
        """Return the configured organization id.

        Returns:
            str: root resource ID.
        """

        raise NotImplementedError()

    def get_gsuite_admin_email(self):
        """Return the gsuite admin email to use.

        Returns:
            str: Gsuite admin email.
        """

        raise NotImplementedError()

    def get_service_config(self):
        """Return the attached service configuration.

        Returns:
            object: Service configuration.
        """

        raise NotImplementedError()

    def set_service_config(self, service_config):
        """Attach a service configuration.

        Args:
            service_config (object): Service configuration.
        """

        raise NotImplementedError()

    def get_replay_file(self):
        """Return the replay file which is None most of the time.

        Returns:
            str: File to replay GCP API calls from.
        """

        raise NotImplementedError()

    def get_record_file(self):
        """Return the record file which is None most of the time.

        Returns:
            str: File to record GCP API calls to.
        """

        raise NotImplementedError()


class MockServerConfig(AbstractServiceConfig):

    def __init__(self, *args, **kwargs):
        super(MockServerConfig, self).__init__(*args, **kwargs)

    def get_engine(self):
        """Get the database engine."""

        raise NotImplementedError()

    def scoped_session(self):
        """Get a scoped session."""

        raise NotImplementedError()

    def client(self):
        """Get an API client."""

        raise NotImplementedError()

    def run_in_background(self, func):
        """Runs a func in a thread pool in the background."""

        raise NotImplementedError()

    def get_storage_class(self):
        """Returns an inventory storage implementation class."""

        raise NotImplementedError()

    def get_inventory_config(self):
        """Get the inventory config."""

        raise NotImplementedError()
