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

""" Unit Tests: Inventory crawler for IAM Explain. """

import unittest

from tests.unittest_utils import ForsetiTestCase
from google.cloud.security.inventory2.storage import Memory as MemoryStorage
from google.cloud.security.inventory2.crawler import Crawler
from google.cloud.security.inventory2.progress import Progresser
from google.cloud.security.iam.inventory.crawler import run_crawler


class NullProgresser(Progresser):
    """No-op progresser to suppress output"""
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
        ForsetiTestCase.setUp(self)

    def tearDown(self):
        """Tear down method."""
        ForsetiTestCase.tearDown(self)

    def test_crawling_to_memmory_storage(self):
        """Crawl an environment, test that there are items in storage."""

        gsuite_sa = '/Users/fmatenaar/deployments/forseti/groups.json'
        with MemoryStorage() as storage:
            progresser = NullProgresser()
            run_crawler(storage, progresser, gsuite_sa)
            self.assertEqual(0,
                             progresser.errors,
                             'No errors should have occurred')


if __name__ == '__main__':
    unittest.main()
