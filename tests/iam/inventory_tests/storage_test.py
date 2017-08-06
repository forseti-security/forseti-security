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

""" Unit Tests: Inventory storage for IAM Explain. """

import unittest

from tests.unittest_utils import ForsetiTestCase
from google.cloud.security.iam.inventory.storage import Storage


class ResourceMock:
    def __init__(self, key, data, res_type):
        self._key = key
        self._data = data
        self._res_type = res_type

    def type(self):
        return self._res_type

    def key(self):
        return self._key

    def data(self):
        return self._data

    def getIamPolicy(self):
        return {}

    def getGCSPolicy(self):
        return {}


class StorageTest(ForsetiTestCase):
    """Test inventory storage."""

    def setUp(self):
        """Setup method."""
        ForsetiTestCase.setUp(self)

    def tearDown(self):
        """Tear down method."""
        ForsetiTestCase.tearDown(self)

    def reduced_inventory(self, storage, types):
        result = (
            [x for x in storage.iterinventory(types)])
        return result

    def test_basic(self):
        """Test storing a few resources, then iterate."""
        MEMORY_DB = 'sqlite:///:memory:'

        resources = [
                ResourceMock('1', {'id': 'test'}, 'organization'),
                ResourceMock('2', {'id': 'test'}, 'project'),
                ResourceMock('3', {'id': 'test'}, 'bucket'),
                ResourceMock('4', {'id': 'test'}, 'project'),
                ResourceMock('5', {'id': 'test'}, 'bucket'),
                ResourceMock('6', {'id': 'test'}, 'object'),
            ]

        with Storage(MEMORY_DB) as storage:
            for resource in resources:
                storage.write(resource)

            self.assertEqual(3,
                             len(self.reduced_inventory(
                                 storage,
                                 ['organization', 'bucket'])),
                             'Only 1 organization and 2 buckets')

            self.assertEqual(6,
                             len(self.reduced_inventory(storage, [])),
                             'No types should yield empty list')

        storage = Storage(MEMORY_DB)
        _ = storage.open()
        for resource in resources:
            storage.write(resource)
        self.assertEqual(3,
                         len(self.reduced_inventory(
                             storage,
                             ['organization', 'bucket'])),
                         'Only 1 organization and 2 buckets')

        self.assertEqual(6,
                         len(self.reduced_inventory(storage, [])),
                         'No types should yield empty list')

        storage.close()


if __name__ == '__main__':
    unittest.main()

