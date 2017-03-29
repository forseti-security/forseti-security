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

"""Base pipeline to load data into inventory."""

import abc

from google.cloud.security.common.data_access import errors as data_access_errors
from google.cloud.security.common.util.log_util import LogUtil


class _BasePipeline(object):
    """Base client for a specified GCP API and credentials."""

    __metaclass__ = abc.ABCMeta

    def __init__(self, name, cycle_timestamp, configs, gcp_api_client, dao):
        """Constructor for the base pipeline.

        Args:
            name: String of the resource loaded by the pipeline.
            cycle_timestamp: String of timestamp, formatted as YYYYMMDDTHHMMSSZ.
            configs: Dictionary of configurations.
            gcp_api_client: GCP API client object.
            dao: Data access object.

        Returns:
            None
        """
        self.logger = LogUtil.setup_logging(__name__)
        self.name = name
        self.cycle_timestamp = cycle_timestamp
        self.configs = configs
        self.gcp_api_client = gcp_api_client
        self.dao = dao

    @abc.abstractmethod
    def run(self):
        """Runs the pipeline."""
        pass

    @abc.abstractmethod
    def _retrieve(self):
        """Retrieve resource data from source."""
        pass

    @abc.abstractmethod
    def _flatten(self):
        """Transformation to flatten data into loadable format."""
        pass

    @abc.abstractmethod
    def _load(self):
        """Load data into Cloud SQL."""
        pass

    def _get_loaded_count(self):
        """Get the count of how many of a resource has been loaded."""
        try:
            self.count = self.dao.select_record_count(
                self.name,
                self.cycle_timestamp)
        except data_access_errors.MySQLError as e:
            self.logger.error('Unable to retrieve record count for %s_%s:\n%s',
                self.name, self.cycle_timestamp, e)
            self.count = None

    def _parse_member_info(self, member):
        """Parse out the component info in the member string.

        Args:
            member: String of a member.  Example: user:foo@bar.com
    
        Returns:
            member_type: String of the member type.
            member_name: String of the name portion of the member.
            member_domain: String of the domain of the member.
        """
        member_type, email = member.split(":", 1)
    
        if '@' in email:
            member_name, member_domain = email.split('@', 1)
        else:
            # member is really something like domain:google.com
            member_name = ''
            member_domain = email
    
        return member_type, member_name, member_domain
