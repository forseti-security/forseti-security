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

"""Pipeline to load appengine applications into Inventory."""

import json

from google.cloud.security.common.data_access import project_dao as proj_dao
from google.cloud.security.common.util import log_util
from google.cloud.security.inventory.pipelines import base_pipeline


LOGGER = log_util.get_logger(__name__)


class LoadServiceAccountsPipeline(base_pipeline.BasePipeline):
    """Load all Service Accounts for all projects."""

    RESOURCE_NAME = 'service_accounts'

    def _retrieve(self):
        """Retrieve Service Accounts from GCP.

        Returns:
            dict: Mapping projects with their Service Accounts:
            {project_id: application}
        """
        projects = (
            proj_dao
            .ProjectDao(self.global_configs)
            .get_projects(self.cycle_timestamp))
        service_accounts_per_project = {}
        for project in projects:
            service_accounts = self.api_client.get_service_accounts(project.id)
            if service_accounts:
                service_accounts = list(service_accounts)
                for service_account in service_accounts:
                    service_account['keys'] = (self.api_client
                        .get_service_account_keys(service_account['name'])['keys'])
                service_accounts_per_project[project.id] = service_accounts
        return service_accounts_per_project

    def _transform(self, resource_from_api):
        """Create an iterator of Service Accounts to load into database.

        Args:
            resource_from_api (dict): Service Accounts, keyed by
                project id, from GCP API.

        Yields:
            iterator: Service Accounts in a dict.
        """
        foo = {}
        for project_id, service_accounts in resource_from_api.iteritems():
            for service_account in service_accounts:
                yield {
                    'project_id': project_id,
                    'name': service_account.get('name'),
                    'email': service_account.get('email'),
                    'oauth2_client_id': service_account.get('oauth2ClientId'),
                    'account_keys': json.dumps(service_account.get('keys')),
                    'raw_service_account': json.dumps(service_account),
                }

    def run(self):
        """Run the pipeline."""
        service_accounts = self._retrieve()
        loadable_service_accounts = self._transform(service_accounts)
        self._load(self.RESOURCE_NAME, loadable_service_accounts)
        self._get_loaded_count()
