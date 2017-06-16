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

from google.cloud.security.common.gcp_api import errors as api_errors
from google.cloud.security.common.util import log_util
from google.cloud.security.common.util import parser
from google.cloud.security.inventory import errors as inventory_errors
from google.cloud.security.inventory.pipelines import base_pipeline


# TODO: The next editor must remove this disable and correct issues.
# pylint: disable=missing-yield-type-doc,missing-type-doc


LOGGER = log_util.get_logger(__name__)


class LoadOrgsPipeline(base_pipeline.BasePipeline):
    """Pipeline to load org IAM policies data into Inventory."""

    RESOURCE_NAME = 'organizations'

    def _transform(self, resource_from_api):
        """Yield an iterator of loadable organizations.

        Args:
            resource_from_api: An iterable of resource manager org search
                response.
                https://cloud.google.com/resource-manager/reference/rest/v1/organizations/search
                https://cloud.google.com/resource-manager/reference/rest/v1/organizations#Organization

        Yields:
            An iterable of loadable orgs, each org as a dict.
        """
        for org in (o for d in resource_from_api for o in d.get(
                'organizations', [])):
            # org_name is the unique identifier for the org, formatted as
            # "organizations/<organization_id>".
            org_name = org.get('name')
            org_id = org_name[len('%s/' % self.RESOURCE_NAME):]

            yield {'org_id': org_id,
                   'name': org_name,
                   'display_name': org.get('displayName'),
                   'lifecycle_state': org.get('lifecycleState'),
                   'raw_org': parser.json_stringify(org),
                   'creation_time': parser.format_timestamp(
                       org.get('creationTime'),
                       self.MYSQL_DATETIME_FORMAT)}

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
