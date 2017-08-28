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

os.environ['GCP_API_REPLAY'] = 'ENABLED'
os.environ['GCP_API_FILE'] = '/tmp/pickled.test'

from tests.unittest_utils import ForsetiTestCase
from google.cloud.security.inventory2.storage import Memory as MemoryStorage
from google.cloud.security.inventory2.progress import Progresser
from google.cloud.security.iam.inventory.crawler import run_crawler
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
    def test_recprd_gcp_api2(self):
        """Crawl an environment, test that there are items in storage."""

        gcp = gcp_env()
        gsuite_sa = gcp.gsuite_sa
        gsuite_admin_email = gcp.gsuite_admin_email
        organization_id = gcp.organization_id

        with MemoryStorage() as storage:
            progresser = NullProgresser()
            run_crawler(storage,
                        progresser,
                        gsuite_sa,
                        gsuite_admin_email,
                        organization_id)

            self.assertEqual(0,
                             progresser.errors,
                             'No errors should have occurred')

        types = set([item.type() for item in storage.mem.values()])
        self.assertEqual(len(types), 17, """"The inventory crawl 18 types of
        resources in a well populated organization, howevever, there is: """
        +str(len(types)))

    def test_replay_gcp_api2(self):
        """Replay recorded GCP API responses to emulate a GCP environment."""

        gsuite_sa = ""
        gsuite_admin_email = ""
        organization_id = "660570133860"
        test_file = get_api_file_path('henry_gbiz_08282017.pickled')

        with MemoryStorage() as storage:
            progresser = NullProgresser()
            run_crawler(storage,
                        progresser,
                        gsuite_sa,
                        gsuite_admin_email,
                        organization_id,
                        replay_file=test_file)

            self.assertEqual(0,
                             progresser.errors,
                             'No errors should have occurred')

        types = set([item.type() for item in storage.mem.values()])
        self.assertEqual(len(types), 16, """"The inventory crawl 16 types of
        resources in a well populated organization, howevever, there is: """
        +str(len(types)))


if __name__ == '__main__':
    unittest.main()
