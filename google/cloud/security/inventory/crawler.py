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

""" Crawler implementation. """

# TODO: Remove this when time allows
# pylint: disable=missing-type-doc,missing-return-type-doc,missing-return-doc
# pylint: disable=missing-param-doc

from google.cloud.security.iam.inventory.inventory2 import gcp
from google.cloud.security.inventory import base_crawler
from google.cloud.security.inventory import resources


class CrawlerConfig(base_crawler.CrawlerConfig):
    """Crawler configuration to inject dependencies."""

    def __init__(self, storage, progresser, api_client, variables=None):
        super(CrawlerConfig, self).__init__()
        self.storage = storage
        self.progresser = progresser
        self.variables = {} if not variables else variables
        self.client = api_client


class Crawler(base_crawler.Crawler):
    """Simple single-threaded Crawler implementation."""

    def __init__(self, config):
        super(Crawler, self).__init__()
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

    def dispatch(self, callback):
        """Dispatch crawling of a subtree.

        Args:
            callback (function): Callback to dispatch.
        """

        callback()

    def get_client(self):
        """Get the GCP API client."""

        return self.config.client


def run_crawler(storage,
                progresser,
                config):
    """Run the crawler with a determined configuration.

    Args:
        storage (object): Storage implementation to use.
        progresser (object): Progresser to notify status updates.
        config (object): Inventory configuration.
    """

    client_config = {
        'groups_service_account_key_file': config.get_gsuite_sa_path(),
        'domain_super_admin_email': config.get_gsuite_admin_email(),
        'max_admin_api_calls_per_day': 150000,
        'max_appengine_api_calls_per_second': 20,
        'max_bigquery_api_calls_per_100_seconds': 17000,
        'max_crm_api_calls_per_100_seconds': 400,
        'max_sqladmin_api_calls_per_100_seconds': 100,
        'max_compute_api_calls_per_second': 20,
        'max_iam_api_calls_per_second': 20,
        'replay_file': config.get_replay_file(),
        'record_file': config.get_record_file(),
        }

    root_id = config.get_root_resource_id()
    client = gcp.ApiClientImpl(client_config)
    resource = resources.from_root_id(client, root_id)
    config = CrawlerConfig(storage, progresser, client)
    crawler_impl = Crawler(config)
    progresser = crawler_impl.run(resource)
    return progresser.get_summary()
