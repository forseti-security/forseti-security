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

"""Inventory loader script test."""

from datetime import datetime

import mock
import MySQLdb

from google.apputils import basetest
from google.cloud.security.common.data_access import dao
from google.cloud.security.common.data_access import errors
from google.cloud.security.common.gcp_type import iam_policy
from google.cloud.security.common.gcp_type import organization
from google.cloud.security.common.gcp_type import project
from google.cloud.security.common.gcp_type import resource
from google.cloud.security.inventory import inventory_loader
from google.cloud.security.scanner.audit import org_rules_engine as ore


class InventoryLoaderTest(basetest.TestCase):

    @mock.patch.object(inventory_loader, 'FLAGS')
    @mock.patch.object(inventory_loader, 'LOGGER')
    def setUp(self, mock_logger, mock_flags):
        self.fake_timestamp = '123456'
        self.mock_logger = mock_logger


if __name__ == '__main__':
    basetest.main()
