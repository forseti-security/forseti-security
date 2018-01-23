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

"""Inventory loader script test."""

from collections import namedtuple

import mock
import unittest

from tests.unittest_utils import ForsetiTestCase
from google.cloud.security.inventory import inventory_loader


_PIPELINE = namedtuple('Pipeline', ['RESOURCE_NAME', 'status'])


class InventoryLoaderTest(ForsetiTestCase):

    @mock.patch.object(inventory_loader, 'FLAGS')
    @mock.patch.object(inventory_loader, 'LOGGER')
    def setUp(self, mock_logger, mock_flags):
        self.fake_timestamp = '123456'
        self.mock_logger = mock_logger

    def testPostrocessWithFailedGroupsInventory(self):
        pipelines = [
                _PIPELINE('groups', 'FAILURE'),
                _PIPELINE('service_accounts', 'SUCCESS'),
                _PIPELINE('group_members', 'SUCCESS')]
        statuses = [False, True, True]
        expected = [False, True, False]
        actual = inventory_loader._postprocess_statuses(pipelines, statuses)
        self.assertEqual(expected, actual)
        self.assertEqual('FAILURE', pipelines[2].status)

    def testPostrocessWithGroupsInventorySuccess(self):
        pipelines = [
                _PIPELINE('groups', 'SUCCESS'),
                _PIPELINE('service_accounts', 'SUCCESS'),
                _PIPELINE('group_members', 'SUCCESS')]
        statuses = [True] * 3
        actual = inventory_loader._postprocess_statuses(pipelines, statuses)
        self.assertEqual(statuses, actual)

    def testPostrocessWithFailedGroupMembersInventory(self):
        pipelines = [
                _PIPELINE('groups', 'SUCCESS'),
                _PIPELINE('service_accounts', 'SUCCESS'),
                _PIPELINE('group_members', 'FAILURE')]
        statuses = [True, True, False]
        actual = inventory_loader._postprocess_statuses(pipelines, statuses)
        self.assertEqual(statuses, actual)

if __name__ == '__main__':
    unittest.main()
