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
import os

from tests.unittest_utils import ForsetiTestCase
from google.cloud.security.inventory2.storage import Memory as MemoryStorage
from google.cloud.security.inventory2.progress import Progresser
from google.cloud.security.iam.inventory.crawler import run_crawler
from google.cloud.security.iam.server import InventoryConfig

from tests.iam.utils.gcp_env import gcp_configured, gcp_env


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


def get_api_file_path(filename):
    module_dir = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(module_dir, 'test_data', filename)


class CrawlerTest(ForsetiTestCase):
    """Test inventory storage."""

    def setUp(self):
        """Setup method."""

        ForsetiTestCase.setUp(self)

    def tearDown(self):
        """Tear down method."""

        ForsetiTestCase.tearDown(self)

    @unittest.skipUnless(gcp_configured(), "requires a real gcp environment")
    def test_record_gcp_api2(self):
        """Crawl an environment, test that there are items in storage."""

        gcp = gcp_env()
        test_file = get_api_file_path('henry_gbiz_08282017.pickled')
        config = InventoryConfig(gcp.organization_id,
                                 gcp.gsuite_sa,
                                 gcp.gsuite_admin_email,
                                 record_file=test_file)
        progresser = NullProgresser()

        with MemoryStorage() as storage:
            run_crawler(storage,
                        progresser,
                        config)

            self.assertEqual(0,
                             progresser.errors,
                             'No errors should have occurred')

        types = set([item.type() for item in storage.mem.values()])
        msg = "The inventory crawl 16 types of resources in a well populated\
        organization, howevever, there is: {}"
        self.assertEqual(len(types), 16, msg.format(len(types)))

    @unittest.skipIf(gcp_configured(), "Don't replay when recordings run")
    def test_replay_gcp_api2(self):
        """Replay recorded GCP API responses to emulate a GCP environment."""

        gsuite_sa = ""
        gsuite_admin_email = ""
        organization_id = "660570133860"

        test_file = get_api_file_path('henry_gbiz_08282017.pickled')
        config = InventoryConfig(organization_id,
                                 gsuite_sa,
                                 gsuite_admin_email,
                                 replay_file=test_file)

        with MemoryStorage() as storage:
            progresser = NullProgresser()
            run_crawler(storage,
                        progresser,
                        config)

            self.assertEqual(0,
                             progresser.errors,
                             'No errors should have occurred')

        types = set([item.type() for item in storage.mem.values()])
        msg = "The inventory crawl 16 types of resources in a well populated\
        organization, howevever, there is: {}"
        self.assertEqual(len(types), 16, msg.format(len(types)))


if __name__ == '__main__':
    unittest.main()
