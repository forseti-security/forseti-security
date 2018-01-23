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

import mock
import unittest

from tests.unittest_utils import ForsetiTestCase
from google.cloud.security.inventory import inventory_loader


class _PIPELINE(object):
    """Mock `Pipeline` class."""
    def __init__(this, RESOURCE_NAME, status):
        this.RESOURCE_NAME = RESOURCE_NAME
        this.status = status


class InventoryLoaderTest(ForsetiTestCase):
    """Unit tests for the `inventory_loader` module."""

    def testPostprocessWithFailedGroupsInventory(self):
        pipelines = [
                _PIPELINE('groups', 'FAILURE'),
                _PIPELINE('service_accounts', 'SUCCESS'),
                _PIPELINE('group_members', 'SUCCESS')]
        statuses = [False, True, True]
        expected = [False, True, False]
        self.assertTrue(
            inventory_loader._postprocess_statuses(pipelines, statuses))
        self.assertEqual(expected, statuses)
        self.assertEqual('FAILURE', pipelines[2].status)

    def testPostprocessWithGroupsInventorySuccess(self):
        pipelines = [
                _PIPELINE('groups', 'SUCCESS'),
                _PIPELINE('service_accounts', 'SUCCESS'),
                _PIPELINE('group_members', 'SUCCESS')]
        statuses = [True] * 3
        self.assertFalse(
            inventory_loader._postprocess_statuses(pipelines, statuses))

    def testPostprocessWithoutGroupsInventory(self):
        pipelines = [
                _PIPELINE('instances', 'SUCCESS'),
                _PIPELINE('service_accounts', 'SUCCESS'),
                _PIPELINE('group_members', 'FAILURE')]
        statuses = [True, True, False]
        self.assertFalse(
            inventory_loader._postprocess_statuses(pipelines, statuses))

    def testPostprocessWithoutGroupmembersInventory(self):
        pipelines = [
                _PIPELINE('instances', 'SUCCESS'),
                _PIPELINE('service_accounts', 'SUCCESS'),
                _PIPELINE('groups', 'FAILURE')]
        statuses = [True, True, False]
        self.assertFalse(
            inventory_loader._postprocess_statuses(pipelines, statuses))

    def testPostprocessWithFailedGroupMembersInventory(self):
        pipelines = [
                _PIPELINE('groups', 'SUCCESS'),
                _PIPELINE('service_accounts', 'SUCCESS'),
                _PIPELINE('group_members', 'FAILURE')]
        statuses = [True, True, False]
        self.assertFalse(
            inventory_loader._postprocess_statuses(pipelines, statuses))

if __name__ == '__main__':
    unittest.main()
