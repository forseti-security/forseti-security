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

""" Inventory API. """

# TODO: The next editor must remove this disable and correct issues.
# pylint: disable=missing-type-doc,missing-return-type-doc,missing-return-doc
# pylint: disable=missing-param-doc

from Queue import Queue

from google.cloud.security.iam.inventory.storage import DataAccess
from google.cloud.security.inventory2.progress import Progresser as BaseProgresser
from google.cloud.security.common.util.threadpool import ThreadPool


class Progress():
    def get_id(self):
        return self.progress_id

    def get_start_time(self):
        return self.get_start_time

    def get_completion_time(self):
        return self.completion_time

    def get_schema_version(self):
        return self.schema_version

    def get_object_count(self):
        return self.object_count

    def get_status(self):
        return self.status

    def get_warnings(self):
        return self.warnings

    def get_errors(self):
        return self.errors


class NullProgresser(BaseProgresser):
    pass


class QueueProgresser(BaseProgresser):
    pass


def run_inventory(sessionmaker, progresser):
    with sessionmaker() as session:
        client_config = {
                'groups_service_account_key_file': '/Users/fmatenaar/deployments/forseti/groups.json',
                'max_admin_api_calls_per_day': 150000,
                'max_appengine_api_calls_per_second': 20,
                'max_bigquery_api_calls_per_100_seconds': 17000,
                'max_crm_api_calls_per_100_seconds': 400,
                'max_sqladmin_api_calls_per_100_seconds': 100,
                'max_compute_api_calls_per_second': 20,
                'max_iam_api_calls_per_second': 20,
            }
        orgid = 'organizations/660570133860'

        client = gcp.ApiClientImpl(client_config)
        resource = resources.Organization.fetch(client, orgid)

        mem = storage.Memory()
        progresser = progress.CliProgresser()
        config = CrawlerConfig(mem, progresser, client)

        crawler = Crawler(config)
        progresser = crawler.run(resource)
        progresser.print_stats()


def run_import(client, model_name):
    reply = client.explain('INVENTORY', model_name)
    return Pro


# pylint: disable=invalid-name,no-self-use
class Inventory(object):
    """Inventory API implementation."""

    def __init__(self, config):
        self.config = config

    def Create(self, background, model_name):
        """Create a new inventory,

        Args:
            background (bool): Run import in background, return immediately
            model_name (str): Model name to import into
        """

        queue = Queue()

        if background:
            def do_work():
                run_inventory(self.config.session, NullProgresser())
                if model_name:
                    run_import(self.config.client(), model_name)

            self.config.run_in_background(do_work)
            yield Progress()

        else:

            with self.config.session() as session:
                def do_work():
                    run_inventory(session, QueueProgresser(queue))
                    if model_name:
                        run_import(self.config.client(), model_name)

                result = self.config.run_in_background(do_work)
                for progress in iter(queue.get, None):
                    yield progress
                result.get()

    def List(self):
        """List stored inventory.

        Yields:
            object: Inventory metadata
        """

        with self.config.session() as session:
            for item in DataAccess.list(session):
                yield item

    def Get(self, inventory_id):
        """Get inventory metadata by id.

        Args:
            inventory_id (int): Id of the inventory.

        Returns:
            object: Inventory metadata
        """

        with self.config.session() as session:
            return DataAccess.get(session, inventory_id)

    def Delete(self, inventory_id):
        """Delete an inventory by id.

        Args:
            inventory_id (int): Id of the inventory.

        Returns:
            object: Inventory object that was deleted
        """

        with self.config.session() as session:
            return DataAccess.delete(session, inventory_id)
