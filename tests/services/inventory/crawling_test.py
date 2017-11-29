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
"""Unit Tests: Inventory crawler for IAM Explain."""

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
        self.warnings += 1

    def on_error(self, error):
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

    def test_crawling_to_memory_storage(self):
        """Crawl mock environment, test that there are items in storage."""

        config = InventoryConfig(
            gcp_api_mocks.ORGANIZATION_ID,
            '',
            '')

        with MemoryStorage() as storage:
            progresser = NullProgresser()
            with gcp_api_mocks.mock_gcp():
                run_crawler(storage,
                            progresser,
                            config)

            self.assertEqual(0,
                             progresser.errors,
                             'No errors should have occurred')

        result_counts = {}
        for item in storage.mem.values():
            item_type = item.type()
            result_counts.setdefault(item_type, {'resource': 0})
            result_counts[item_type]['resource'] += 1
            if item.getIamPolicy():
                result_counts[item_type].setdefault('iam_policy', 0)
                result_counts[item_type]['iam_policy'] += 1
            if item.getGCSPolicy():
                result_counts[item_type].setdefault('gcs_policy', 0)
                result_counts[item_type]['gcs_policy'] += 1

        expected_counts = {
            'backendservice': {'resource': 1},
            'bucket': {'gcs_policy': 2, 'iam_policy': 2, 'resource': 2},
            'cloudsqlinstance': {'resource': 1},
            'compute_project': {'resource': 2},
            'dataset': {'resource': 1},
            'firewall': {'resource': 7},
            'folder': {'iam_policy': 3, 'resource': 3},
            'gsuite_group': {'resource': 3},
            'gsuite_group_member': {'resource': 1},
            'gsuite_user': {'resource': 3},
            'gsuite_user_member': {'resource': 3},
            'instance': {'resource': 4},
            'instancegroup': {'resource': 1},
            'organization': {'iam_policy': 1, 'resource': 1},
            'project': {'iam_policy': 4, 'resource': 4},
            'role': {'resource': 5},
            'serviceaccount': {'resource': 2}
        }

        self.assertEqual(expected_counts, result_counts)


if __name__ == '__main__':
    unittest.main()
