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
"""Unit Tests: Inventory storage for IAM Explain."""

import unittest
from tests.unittest_utils import ForsetiTestCase
from tests.services.utils.db import create_test_engine
from google.cloud.forseti.services import db
from google.cloud.forseti.services.inventory.base.resources import Resource
from google.cloud.forseti.services.inventory.storage import initialize
from google.cloud.forseti.services.inventory.storage import Storage


class ResourceMock(Resource):

    def __init__(self, key, data, res_type, parent=None, warning=[]):
        self._key = key
        self._data = data
        self._res_type = res_type
        self._parent = parent if parent else self
        self._warning = warning

    def type(self):
        return self._res_type

    def key(self):
        return self._key

    def parent(self):
        return self._parent


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
            [x for x in storage.iter(types)])
        return result

    def test_basic(self):
        """Test storing a few resources, then iterate."""
        engine = create_test_engine()

        initialize(engine)
        sessionmaker = db.create_scoped_sessionmaker(engine)

        res_org = ResourceMock('1', {'id': 'test'}, 'organization')
        res_proj1 = ResourceMock('2', {'id': 'test'}, 'project', res_org)
        res_buc1 = ResourceMock('3', {'id': 'test'}, 'bucket', res_proj1)
        res_proj2 = ResourceMock('4', {'id': 'test'}, 'project', res_org)
        res_buc2 = ResourceMock('5', {'id': 'test'}, 'bucket', res_proj2)
        res_obj2 = ResourceMock('6', {'id': 'test'}, 'object', res_buc2)

        resources = [
            res_org,
            res_proj1,
            res_buc1,
            res_proj2,
            res_buc2,
            res_obj2
        ]

        with sessionmaker() as session:
            with Storage(session) as storage:
                for resource in resources:
                    storage.write(resource)
                storage.commit()

                self.assertEqual(3,
                                 len(self.reduced_inventory(
                                     storage,
                                     ['organization', 'bucket'])),
                                 'Only 1 organization and 2 buckets')

                self.assertEqual(6,
                                 len(self.reduced_inventory(storage, [])),
                                 'No types should yield empty list')

        with sessionmaker() as session:
            storage = Storage(session)
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


if __name__ == '__main__':
    unittest.main()
