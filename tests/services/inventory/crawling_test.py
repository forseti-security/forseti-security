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
"""Unit Tests: Inventory crawler for Forseti Server."""

import logging
import unittest
from tests.services.inventory import gcp_api_mocks
from tests.unittest_utils import ForsetiTestCase
from google.cloud.forseti.services.inventory.base.progress import Progresser
from google.cloud.forseti.services.inventory.base.storage import Memory as MemoryStorage
from google.cloud.forseti.services.inventory.crawler import run_crawler
from google.cloud.forseti.services.server import InventoryConfig


class NullProgresser(Progresser):
    """No-op progresser to suppress output."""

    def __init__(self):
        super(NullProgresser, self).__init__()
        self.errors = 0
        self.objects = 0
        self.warnings = 0

    def on_new_object(self, resource):
        self.objects += 1

    def on_warning(self, warning):
        logging.error("Progressor Warning: %s", warning)
        self.warnings += 1

    def on_error(self, error):
        logging.exception("Progressor Error: %s", error)
        self.errors += 1

    def get_summary(self):
        pass


class CrawlerTest(ForsetiTestCase):
    """Test inventory storage."""

    def setUp(self):
        """Setup method."""
        self.maxDiff = None
        ForsetiTestCase.setUp(self)

    def tearDown(self):
        """Tear down method."""

        ForsetiTestCase.tearDown(self)

    def _get_resource_counts_from_storage(self, storage):
        result_counts = {}
        for item in storage.mem.values():
            item_type = item.type()
            item_counts = result_counts.setdefault(
                item_type, {'resource': 0})
            item_counts['resource'] += 1
            if item.get_iam_policy():
                item_counts.setdefault('iam_policy', 0)
                item_counts['iam_policy'] += 1
            if item.get_gcs_policy():
                item_counts.setdefault('gcs_policy', 0)
                item_counts['gcs_policy'] += 1
            if item.get_dataset_policy():
                item_counts.setdefault('dataset_policy', 0)
                item_counts['dataset_policy'] += 1
            if item.get_billing_info():
                item_counts.setdefault('billing_info', 0)
                item_counts['billing_info'] += 1
            if item.get_enabled_apis():
                item_counts.setdefault('enabled_apis', 0)
                item_counts['enabled_apis'] += 1
            if item.get_kubernetes_service_config():
                item_counts.setdefault('service_config', 0)
                item_counts['service_config'] += 1

        return result_counts

    def test_crawling_to_memory_storage(self):
        """Crawl mock environment, test that there are items in storage."""

        config = InventoryConfig(
            gcp_api_mocks.ORGANIZATION_ID,
            '',
            {},
            '')

        with MemoryStorage() as storage:
            progresser = NullProgresser()
            with gcp_api_mocks.mock_gcp():
                run_crawler(storage,
                            progresser,
                            config,
                            parallel=True)

            self.assertEqual(0,
                             progresser.errors,
                             'No errors should have occurred')

            result_counts = self._get_resource_counts_from_storage(storage)

        expected_counts = {
            'appengine_app': {'resource': 2},
            'appengine_instance': {'resource': 3},
            'appengine_service': {'resource': 1},
            'appengine_version': {'resource': 1},
            'backendservice': {'resource': 1},
            'billing_account': {'resource': 2, 'iam_policy': 2},
            'bucket': {'gcs_policy': 2, 'iam_policy': 2, 'resource': 2},
            'cloudsqlinstance': {'resource': 1},
            'compute_project': {'resource': 2},
            'dataset': {'dataset_policy': 1, 'resource': 1},
            'disk': {'resource': 4},
            'firewall': {'resource': 7},
            'folder': {'iam_policy': 3, 'resource': 3},
            'forwardingrule': {'resource': 1},
            'gsuite_group': {'resource': 4},
            'gsuite_group_member': {'resource': 1},
            'gsuite_user': {'resource': 4},
            'gsuite_user_member': {'resource': 3},
            'image': {'resource': 2},
            'instance': {'resource': 4},
            'instancegroup': {'resource': 2},
            'instancegroupmanager': {'resource': 2},
            'instancetemplate': {'resource': 2},
            'kubernetes_cluster': {'resource': 1, 'service_config': 1},
            'network': {'resource': 2},
            'organization': {'iam_policy': 1, 'resource': 1},
            'project': {'billing_info': 4, 'enabled_apis': 4, 'iam_policy': 4,
                        'resource': 4},
            'role': {'resource': 5},
            'serviceaccount': {'iam_policy': 2, 'resource': 2},
            'serviceaccount_key': {'resource': 1},
            'sink': {'resource': 7},
            'subnetwork': {'resource': 24},
        }

        self.assertEqual(expected_counts, result_counts)

    def test_crawling_from_folder(self):
        """Crawl from folder, verify expected resources crawled."""

        config = InventoryConfig(
            'folders/1032',
            '',
            {},
            '')

        with MemoryStorage() as storage:
            progresser = NullProgresser()
            with gcp_api_mocks.mock_gcp():
                run_crawler(storage,
                            progresser,
                            config,
                            parallel=False)

            self.assertEqual(0,
                             progresser.errors,
                             'No errors should have occurred')

            result_counts = self._get_resource_counts_from_storage(storage)

        expected_counts = {
            'appengine_app': {'resource': 1},
            'appengine_instance': {'resource': 3},
            'appengine_service': {'resource': 1},
            'appengine_version': {'resource': 1},
            'bucket': {'gcs_policy': 1, 'iam_policy': 1, 'resource': 1},
            'folder': {'iam_policy': 2, 'resource': 2},
            'project': {'billing_info': 1, 'enabled_apis': 1, 'iam_policy': 1,
                        'resource': 1},
            'role': {'resource': 1},
            'sink': {'resource': 1},
        }

        self.assertEqual(expected_counts, result_counts)

    def test_crawling_from_project(self):
        """Crawl from project, verify expected resources crawled."""

        config = InventoryConfig(
            'projects/1041',
            '',
            {},
            '')

        with MemoryStorage() as storage:
            progresser = NullProgresser()
            with gcp_api_mocks.mock_gcp():
                run_crawler(storage,
                            progresser,
                            config,
                            parallel=False)

            self.assertEqual(0,
                             progresser.errors,
                             'No errors should have occurred')


            result_counts = self._get_resource_counts_from_storage(storage)

        expected_counts = {
            'backendservice': {'resource': 1},
            'compute_project': {'resource': 1},
            'disk': {'resource': 3},
            'firewall': {'resource': 3},
            'forwardingrule': {'resource': 1},
            'instance': {'resource': 3},
            'instancegroup': {'resource': 2},
            'instancegroupmanager': {'resource': 2},
            'instancetemplate': {'resource': 2},
            'kubernetes_cluster': {'resource': 1, 'service_config': 1},
            'network': {'resource': 1},
            'project': {'billing_info': 1, 'enabled_apis': 1, 'iam_policy': 1,
                        'resource': 1},
            'serviceaccount': {'iam_policy': 1, 'resource': 1},
            'serviceaccount_key': {'resource': 1},
            'sink': {'resource': 2},
            'subnetwork': {'resource': 12},
        }

        self.assertEqual(expected_counts, result_counts)

    def test_crawling_no_org_access(self):
        """Crawl with no access to organization, only child projects."""

        config = InventoryConfig(
            gcp_api_mocks.ORGANIZATION_ID,
            '',
            {},
            '')

        with MemoryStorage() as storage:
            progresser = NullProgresser()
            with gcp_api_mocks.mock_gcp(has_org_access=False):
                run_crawler(storage,
                            progresser,
                            config,
                            parallel=True)

            self.assertEqual(0,
                             progresser.errors,
                             'No errors should have occurred')

            result_counts = self._get_resource_counts_from_storage(storage)

        # The crawl should be the same as test_crawling_to_memory_storage, but
        # without organization iam_policy (needs Org access) or gsuite_*
        # resources (needs directoryCustomerId from Organization).
        expected_counts = {
            'appengine_app': {'resource': 2},
            'appengine_instance': {'resource': 3},
            'appengine_service': {'resource': 1},
            'appengine_version': {'resource': 1},
            'backendservice': {'resource': 1},
            'billing_account': {'resource': 2, 'iam_policy': 2},
            'bucket': {'gcs_policy': 2, 'iam_policy': 2, 'resource': 2},
            'cloudsqlinstance': {'resource': 1},
            'compute_project': {'resource': 2},
            'dataset': {'dataset_policy': 1, 'resource': 1},
            'disk': {'resource': 4},
            'firewall': {'resource': 7},
            'folder': {'iam_policy': 3, 'resource': 3},
            'forwardingrule': {'resource': 1},
            'image': {'resource': 2},
            'instance': {'resource': 4},
            'instancegroup': {'resource': 2},
            'instancegroupmanager': {'resource': 2},
            'instancetemplate': {'resource': 2},
            'kubernetes_cluster': {'resource': 1, 'service_config': 1},
            'network': {'resource': 2},
            'organization': {'resource': 1},
            'project': {'billing_info': 4, 'enabled_apis': 4, 'iam_policy': 4,
                        'resource': 4},
            'role': {'resource': 5},
            'serviceaccount': {'iam_policy': 2, 'resource': 2},
            'serviceaccount_key': {'resource': 1},
            'sink': {'resource': 7},
            'subnetwork': {'resource': 24},
        }

        self.assertEqual(expected_counts, result_counts)


if __name__ == '__main__':
    unittest.main()
