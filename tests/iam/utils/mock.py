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


from google.cloud.security.iam.server import AbstractServiceConfig


class MockServerConfig(AbstractServiceConfig):

    def __init__(self, *args, **kwargs):
        super(MockServerConfig, self).__init__(*args, **kwargs)

    def get_organization_id(self):
        """Get the organization id.

        Returns:
            str: The configure organization id.
        """

        raise NotImplementedError()

    def get_gsuite_sa_path(self):
        """Get path to gsuite service account.

        Returns:
            str: Gsuite admin service account path.
        """

        raise NotImplementedError()

    def get_gsuite_admin_email(self):
        """Get the gsuite admin email.

        Returns:
            str: Gsuite admin email address to impersonate.
        """

        raise NotImplementedError()

    def get_engine(self):
        """Get the database engine.

        Returns:
            object: Database engine object.
        """

        raise NotImplementedError()

    def scoped_session(self):
        """Get a scoped session.

        Returns:
            object: A scoped session.
        """

        raise NotImplementedError()

    def client(self):
        """Get an API client.

        Returns:
            object: API client to use against services.
        """

        raise NotImplementedError()

    def run_in_background(self, function):
        """Runs a function in a thread pool in the background."""

        raise NotImplementedError()

    def get_storage_class(self):
        """Returns an inventory storage implementation class."""

        raise NotImplementedError()
