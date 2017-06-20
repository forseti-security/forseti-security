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
"""A CloudSQL ACL Resource."""


# TODO: The next editor must remove this disable and correct issues.
# pylint: disable=missing-type-doc,missing-return-type-doc,missing-return-doc


class CloudSqlAccessControl(object):
    """CloudSQL ACL Resource."""

    def __init__(self, instance_name, authorized_networks, ssl_enabled,
                 project_number=None):
        """Initialize

        Args:
            instance_name (str): CloudSQL instance name
            authorized_networks (str): Authorized networks for CloudSQL
                instance
            ssl_enabled (str): SSL enabled
            project_number (int): the project number
        """
        self.instance_name = instance_name
        self.authorized_networks = authorized_networks
        self.ssl_enabled = (ssl_enabled == 'True')
        self.project_number = project_number

    def __hash__(self):
        """Return hash of properties.

        Returns:
            hash: returns the hash of the class properties.
        """
        return hash((self.instance_name, self.authorized_networks,
                     self.ssl_enabled, self.project_number))
