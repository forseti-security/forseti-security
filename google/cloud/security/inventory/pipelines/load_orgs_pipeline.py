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

"""Pipeline to load organizations data into Inventory."""

import json

from dateutil import parser as dateutil_parser

# TODO: Investigate improving so the pylint disable isn't needed.
# pylint: disable=line-too-long
from google.cloud.security.common.data_access import errors as data_access_errors
from google.cloud.security.common.gcp_api import errors as api_errors
from google.cloud.security.common.util import log_util
from google.cloud.security.inventory import errors as inventory_errors
from google.cloud.security.inventory.pipelines import base_pipeline
# pylint: enable=line-too-long

LOGGER = log_util.get_logger(__name__)


class LoadOrgsPipeline(base_pipeline.BasePipeline):
    """Pipeline to load org IAM policies data into Inventory."""

    RESOURCE_NAME = 'organizations'

    MYSQL_DATETIME_FORMAT = '%Y-%m-%d %H:%M:%S'

    def __init__(self, cycle_timestamp, configs, crm_client, dao):
        """Constructor for the data pipeline.

        Args:
            cycle_timestamp: String of timestamp, formatted as YYYYMMDDTHHMMSSZ.
            configs: Dictionary of configurations.
            crm_client: CRM API client.
            dao: Data access object.

        Returns:
            None
        """
        super(LoadOrgsPipeline, self).__init__(
            cycle_timestamp, configs, crm_client, dao)

    def _load(self, resource_name, data):
        """ Load iam policies into cloud sql.

        Args:
            resource_name: String of the resource name.
            data: An iterable or a list of data to be uploaded.

        Returns:
            None

        Raises:
            LoadDataPipelineError: An error with loading data has occurred.
        """
        try:
            self.dao.load_data(resource_name, self.cycle_timestamp, data)
        except (data_access_errors.CSVFileError,
                data_access_errors.MySQLError) as e:
            raise inventory_errors.LoadDataPipelineError(e)

    def _transform(self, orgs):
        """Yield an iterator of loadable iam policies.

        Args:
            orgs: An iterable of resource manager org search response.
                  https://cloud.google.com/resource-manager/reference/rest/v1/organizations/search
                  https://cloud.google.com/resource-manager/reference/rest/v1/organizations#Organization

        Yields:
            An iterable of loadable orgs, each org as a dict.
        """
        for org in (o for d in orgs \
                        for o in d.get('organizations', [])):
            org_json = json.dumps(org)
            try:
                parsed_time = dateutil_parser.parse(org.get('creationTime'))
                create_time_fmt = (
                    parsed_time.strftime(self.MYSQL_DATETIME_FORMAT))
            except (TypeError, ValueError) as e:
                LOGGER.error(
                    'Unable to parse creation_time from org: %s\n%s',
                    org.get('creationTime', ''), e)
                create_time_fmt = '0000-00-00 00:00:00'

            # org_name is the unique identifier for the org, formatted as
            # "organizations/<organization_id>".
            org_name = org.get('name')
            org_id = org_name[len('organizations/'):]

            yield {'org_id': org_id,
                   'name': org_name,
                   'display_name': org.get('displayName'),
                   'lifecycle_state': org.get('lifecycleState'),
                   'raw_org': org_json,
                   'creation_time': create_time_fmt}

    def _retrieve(self):
        """Retrieve the organizations resources from GCP.

        Returns:
            An iterable of resource manager org search response.
            https://cloud.google.com/resource-manager/reference/rest/v1/organizations/search
        """
        try:
            return self.api_client.get_organizations(
                self.RESOURCE_NAME)
        except api_errors.ApiExecutionError as e:
            raise inventory_errors.LoadDataPipelineError(e)

    def run(self):
        """Runs the data pipeline."""
        orgs_map = self._retrieve()

        loadable_orgs = self._transform(orgs_map)

        self._load(self.RESOURCE_NAME, loadable_orgs)

        self._get_loaded_count()
