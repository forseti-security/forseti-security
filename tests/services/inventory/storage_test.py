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
"""Unit Tests: Inventory storage for Forseti Server."""


from datetime import datetime
import mock
import os
from sqlalchemy.orm import sessionmaker
import unittest


from tests.services.util.db import create_test_engine
from tests.unittest_utils import ForsetiTestCase


from google.cloud.forseti.services import db
from google.cloud.forseti.services.inventory.base.resources import Resource
from google.cloud.forseti.services.inventory.storage import initialize
from google.cloud.forseti.services.inventory.storage import InventoryIndex
from google.cloud.forseti.services.inventory.storage import Storage
from tests.services.util.db import create_test_engine_with_file



class ResourceMock(Resource):

    def __init__(self, key, data, res_type, category, parent=None, warning=[]):
        self._key = key
        self._data = data
        self._res_type = res_type
        self._catetory = category
        self._parent = parent if parent else self
        self._warning = warning
        self._timestamp = self._utcnow()
        self._inventory_key = None

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
        scoped_sessionmaker = db.create_scoped_sessionmaker(engine)

        res_org = ResourceMock('1', {'id': 'test'}, 'organization', 'resource')
        res_proj1 = ResourceMock('2', {'id': 'test'}, 'project', 'resource',
                                 res_org)
        res_proj1 = ResourceMock('2', {'id': 'test'}, 'project', 'iam_policy',
                                 res_proj1)
        res_proj1 = ResourceMock('2', {'id': 'test'}, 'project', 'billing_info',
                                 res_proj1)
        res_buc1 = ResourceMock('3', {'id': 'test'}, 'bucket', 'resource',
                                res_proj1)
        res_proj2 = ResourceMock('4', {'id': 'test'}, 'project', 'resource',
                                 res_org)
        res_buc2 = ResourceMock('5', {'id': 'test'}, 'bucket', 'resource',
                                res_proj2)
        res_obj2 = ResourceMock('6', {'id': 'test'}, 'object', 'resource',
                                res_buc2)

        resources = [
            res_org,
            res_proj1,
            res_buc1,
            res_proj2,
            res_buc2,
            res_obj2
        ]

        with scoped_sessionmaker() as session:
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

        with scoped_sessionmaker() as session:
            storage = Storage(session)
            _ = storage.open()
            for resource in resources:
                storage.write(resource)
            storage.buffer.flush()
            self.assertEqual(3,
                             len(self.reduced_inventory(
                                 storage,
                                 ['organization', 'bucket'])),
                             'Only 1 organization and 2 buckets')

            self.assertEqual(6,
                             len(self.reduced_inventory(storage, [])),
                             'No types should yield empty list')


    def test_storage_with_timestamps(self):
        """Crawl from project, verify every resource has a timestamp."""

        def verify_resource_timestamps_from_storage(storage):
            for i, item in enumerate(storage.iter(list()), start=1):
                self.assertTrue('timestamp' in item.get_other())
            return i

        engine = create_test_engine()

        initialize(engine)
        scoped_sessionmaker = db.create_scoped_sessionmaker(engine)

        res_org = ResourceMock('1', {'id': 'test'}, 'organization', 'resource')
        with scoped_sessionmaker() as session:
            with Storage(session) as storage:
                storage.write(res_org)
                storage.commit()

                resource_count = (
                    verify_resource_timestamps_from_storage(storage))
                self.assertEqual(1, resource_count,
                                 'Unexpected number of resources in inventory')


class InventoryIndexTest(ForsetiTestCase):
    """Test inventory storage."""

    def setUp(self):
        """Setup method."""
        ForsetiTestCase.setUp(self)
        self.fake_utcnow = datetime(year=1910, month=9, day=8, hour=7, minute=6)
        self.engine, self.dbfile = create_test_engine_with_file()
        _session_maker = sessionmaker()
        self.session = _session_maker(bind=self.engine)
        initialize(self.engine)

    def tearDown(self):
        """Tear down method."""
        os.unlink(self.dbfile)
        ForsetiTestCase.tearDown(self)

    def test_get_summary(self):
        res_org = ResourceMock('1', {'id': 'test'}, 'organization', 'resource')
        res_proj1 = ResourceMock('2', {'id': 'test'}, 'project', 'resource',
                                 res_org)
        res_proj1 = ResourceMock('3', {'id': 'test'}, 'project', 'iam_policy',
                                 res_proj1)
        res_proj1 = ResourceMock('4', {'id': 'test'}, 'project', 'billing_info',
                                 res_proj1)
        res_buc1 = ResourceMock('5', {'id': 'test'}, 'bucket', 'resource',
                                res_proj1)
        res_proj2 = ResourceMock('6', {'id': 'test'}, 'project', 'resource',
                                 res_org)
        res_buc2 = ResourceMock('7', {'id': 'test'}, 'bucket', 'resource',
                                res_proj2)
        res_obj2 = ResourceMock('8', {'id': 'test'}, 'object', 'resource',
                                res_buc2)
        resources = [
            res_org, res_proj1, res_buc1, res_proj2, res_buc2, res_obj2]

        storage = Storage(self.session)
        inv_index_id = storage.open()
        for resource in resources:
            storage.write(resource)
        storage.commit()
        # add more resource data that belongs to a different inventory index
        storage = Storage(self.session)
        storage.open()
        for resource in resources:
            storage.write(resource)
        storage.commit()

        inv_index = self.session.query(InventoryIndex).get(inv_index_id)
        expected = {'bucket': 2, 'object': 1, 'organization': 1, 'project': 2}
        inv_summary = inv_index.get_summary(self.session)
        self.assertEquals(expected, inv_summary)


if __name__ == '__main__':
    unittest.main()
