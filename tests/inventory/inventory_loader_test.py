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

import copy
import mock
import unittest

from tests.unittest_utils import ForsetiTestCase
from google.cloud.security.inventory import inventory_loader


class _PIPELINE(object):
    """Mock `Pipeline` class."""
    def __init__(self, RESOURCE_NAME, status):
        self.RESOURCE_NAME = RESOURCE_NAME
        self.status = status


class InventoryLoaderTest(ForsetiTestCase):
    """Unit tests for the `inventory_loader` module."""

    a_copy = None
    b_copy = None

    def _take_snapshot(self, a, b):
        """Take a shallow copy of the data passed for a later comparison."""
        self.a_copy = copy.copy(a)
        self.b_copy = copy.copy(b)

    def _equals_the_originals(self, a, b):
        """True if the data passed equals the most recent snapshots."""
        return (self.a_copy == a) and (self.b_copy == b)

    def test_adjust_group_members_status_with_failed_groups_inventory(self):
        pipelines = [
                _PIPELINE('groups', 'FAILURE'),
                _PIPELINE('service_accounts', 'SUCCESS'),
                _PIPELINE('group_members', 'SUCCESS')]
        statuses = [False, True, True]
        expected = [False, True, False]
        self._take_snapshot(pipelines, statuses)
        inventory_loader._adjust_group_members_status(pipelines, statuses)
        self.assertEqual(expected, statuses)
        self.assertEqual('FAILURE', pipelines[2].status)
        self.assertFalse(self._equals_the_originals(pipelines, statuses))

    def test_adjust_group_members_status_with_groups_inventory_success(self):
        pipelines = [
                _PIPELINE('groups', 'SUCCESS'),
                _PIPELINE('service_accounts', 'SUCCESS'),
                _PIPELINE('group_members', 'SUCCESS')]
        statuses = [True] * 3
        self._take_snapshot(pipelines, statuses)
        inventory_loader._adjust_group_members_status(pipelines, statuses)
        self.assertTrue(self._equals_the_originals(pipelines, statuses))

    def test_adjust_group_members_status_without_groups_inventory(self):
        pipelines = [
                _PIPELINE('instances', 'SUCCESS'),
                _PIPELINE('service_accounts', 'SUCCESS'),
                _PIPELINE('group_members', 'FAILURE')]
        statuses = [True, True, False]
        self._take_snapshot(pipelines, statuses)
        inventory_loader._adjust_group_members_status(pipelines, statuses)
        self.assertTrue(self._equals_the_originals(pipelines, statuses))

    def test_adjust_group_members_status_with_both_groups_and_members_failed(self):
        pipelines = [
                _PIPELINE('groups', 'FAILURE'),
                _PIPELINE('service_accounts', 'FAILURE'),
                _PIPELINE('group_members', 'FAILURE')]
        statuses = [False] * 3
        self._take_snapshot(pipelines, statuses)
        inventory_loader._adjust_group_members_status(pipelines, statuses)
        self.assertTrue(self._equals_the_originals(pipelines, statuses))

    def test_adjust_group_members_status_without_group_members_inventory(self):
        pipelines = [
                _PIPELINE('instances', 'SUCCESS'),
                _PIPELINE('service_accounts', 'SUCCESS'),
                _PIPELINE('groups', 'FAILURE')]
        statuses = [True, True, False]
        self._take_snapshot(pipelines, statuses)
        inventory_loader._adjust_group_members_status(pipelines, statuses)
        self.assertTrue(self._equals_the_originals(pipelines, statuses))

    def test_adjust_group_members_status_with_failed_group_members_inventory(self):
        pipelines = [
                _PIPELINE('groups', 'SUCCESS'),
                _PIPELINE('service_accounts', 'SUCCESS'),
                _PIPELINE('group_members', 'FAILURE')]
        statuses = [True, True, False]
        self._take_snapshot(pipelines, statuses)
        inventory_loader._adjust_group_members_status(pipelines, statuses)
        self.assertTrue(self._equals_the_originals(pipelines, statuses))

if __name__ == '__main__':
    unittest.main()
