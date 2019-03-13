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

"""Forseti installer config object."""

import datetime
import hashlib


class Config(object):
    """Forseti installer config object."""
    # pylint: disable=too-many-instance-attributes
    # Having eight variables is reasonable in this case.

    def __init__(self, **kwargs):
        """Initialize.

        Args:
            kwargs (dict): The kwargs.
        """
        self.datetimestamp = (kwargs.get('datetimestamp') or
                              datetime.datetime.now().strftime('%Y%m%d%H%M%S'))
        self.identifier = None
        self.force_no_cloudshell = bool(kwargs.get('no_cloudshell'))
        self.project_id = kwargs.get('project_id')
        if kwargs.get('composite_root_resources'):
            tmpcrr = kwargs.get('composite_root_resources')
            self.composite_root_resources = tmpcrr.split(',')
        else:
            self.composite_root_resources = []
        self.service_account_key_file = kwargs.get('service_account_key_file')
        self.vpc_host_project_id = kwargs.get('vpc_host_project_id')
        self.vpc_host_network = kwargs.get('vpc_host_network') or 'default'
        self.vpc_host_subnetwork = (
            kwargs.get('vpc_host_subnetwork') or 'default')
        self.config_filename = (kwargs.get('config') or
                                'forseti-setup-{}.cfg'.format(
                                    self.datetimestamp))
        self.bucket_location = kwargs.get('gcs_location')
        self.installation_type = None

    def generate_identifier(self, organization_id):
        """Generate resource unique identifier.

        Hash the timestamp and organization id and take the first 7 characters.

        Lowercase is needed because some resource name are not allowed to have
        uppercase.

        The reason why we need to use the hash as the identifier is to ensure
        global uniqueness of the bucket names.

        Args:
            organization_id (str): Organization id.
        """
        if not self.identifier:
            message = organization_id + self.datetimestamp

            hashed_message = hashlib.sha1(message.encode('UTF-8')).hexdigest()

            self.identifier = hashed_message[:7].lower()
