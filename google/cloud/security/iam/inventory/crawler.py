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

""" Crawler implementation. """

# TODO: Remove this when time allows
# pylint: disable=missing-type-doc,missing-return-type-doc,missing-return-doc
# pylint: disable=missing-param-doc

from google.cloud.security.inventory2 import resources
from google.cloud.security.inventory2 import gcp


class CrawlerConfig(dict):
    """Crawler configuration to inject dependencies."""

    def __init__(self, storage, progresser, api_client, variables={}):
        self.storage = storage
        self.progresser = progresser
        self.variables = variables
        self.client = api_client


class Crawler(object):
    """Simple single-threaded Crawler implementation."""

    def __init__(self, config):
        self.config = config

    def run(self, resource):
        """Run the crawler, given a start resource.

        Args:
            resource (object): Resource to start with.
        """

        resource.accept(self)
        return self.config.progresser

    def visit(self, resource):
        """Handle a newly found resource.

        Args:
            resource (object): Resource to handle.

        Raises:
            Exception: Reraises any exception.
        """

        storage = self.config.storage
        progresser = self.config.progresser
        try:

            resource.getIamPolicy(self.get_client())
            resource.getGCSPolicy(self.get_client())
            resource.getDatasetPolicy(self.get_client())
            resource.getCloudSQLPolicy(self.get_client())

            storage.write(resource)
        except Exception as e:
            progresser.on_error(e)
            raise
        else:
            progresser.on_new_object(resource)

    def dispatch(self, resource_visit):
        """Dispatch crawling of a subtree.

        Args:
            resource_visit (function): Callback to dispatch.
        """

        resource_visit()

    def get_client(self):
        """Get the GCP API client."""

        return self.config.client


def run_crawler(storage,
                progresser,
                gsuite_sa,
                gsuite_admin_email,
                organization_id):
    """Run the crawler with a determined configuration.

    Args:
        storage (object): Storage implementation to use.
        progresser (object): Progresser to notify status updates.
        gsuite_sa (str): Gsuite service account to use.
        gsuite_admin_email (str): Gsuite admin email to impersonate.
        organization_id (str): Organization id to crawl.
    """

    client_config = {
        'groups_service_account_key_file': gsuite_sa,
        'domain_super_admin_email': gsuite_admin_email,
        'max_admin_api_calls_per_day': 150000,
        'max_appengine_api_calls_per_second': 20,
        'max_bigquery_api_calls_per_100_seconds': 17000,
        'max_crm_api_calls_per_100_seconds': 400,
        'max_sqladmin_api_calls_per_100_seconds': 100,
        'max_compute_api_calls_per_second': 20,
        'max_iam_api_calls_per_second': 20,
        }

    orgid = 'organizations/{}'.format(organization_id)

    client = gcp.ApiClientImpl(client_config)
    resource = resources.Organization.fetch(client, orgid)

    config = CrawlerConfig(storage, progresser, client)
    crawler = Crawler(config)
    progresser = crawler.run(resource)
    return progresser.get_summary()
