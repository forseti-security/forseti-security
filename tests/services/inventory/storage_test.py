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


from future import standard_library
standard_library.install_aliases()
from datetime import datetime
import time
import unittest.mock as mock
import os
from io import StringIO
import unittest
from sqlalchemy.orm import sessionmaker

from tests.services.util.db import create_test_engine
from tests.services.util.db import create_test_engine_with_file
from tests.services.util.mock import ResourceMock
from tests.unittest_utils import ForsetiTestCase

from google.cloud.forseti.services import db
from google.cloud.forseti.services.inventory.storage import DataAccess
from google.cloud.forseti.services.inventory.storage import initialize
from google.cloud.forseti.services.inventory.storage import InventoryIndex
from google.cloud.forseti.services.inventory.storage import Storage



class StorageTest(ForsetiTestCase):
    """Test inventory storage."""

    def setUp(self):
        """Setup method."""
        self.engine, self.dbfile = create_test_engine_with_file()

        ForsetiTestCase.setUp(self)

    def tearDown(self):
        """Tear down method."""
        os.unlink(self.dbfile)
        mock.patch.stopall()
        ForsetiTestCase.tearDown(self)

    def reduced_inventory(self, session, inventory_index_id, types):
        result = (
            [x for x in DataAccess.iter(session,
                                        inventory_index_id,
                                        types)])
        return result

    def test_basic(self):
        """Test storing a few resources, then iterate."""

        initialize(self.engine)
        scoped_sessionmaker = db.create_scoped_sessionmaker(self.engine)

        res_org = ResourceMock('1', {'id': 'test'}, 'organization', 'resource')
        res_proj1 = ResourceMock('2', {'id': 'test'}, 'project', 'resource',
                                 res_org)
        res_proj1.set_iam_policy({'id': 'test'})
        res_proj1.set_billing_info({'id': 'test'})
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
            with Storage(session, self.engine) as storage:
                for resource in resources:
                    storage.write(resource)
                storage.commit()
                inventory_index_id = storage.inventory_index.id
                self.assertEqual(3,
                                 len(self.reduced_inventory(
                                     session,
                                     inventory_index_id,
                                     ['organization', 'bucket'])),
                                 'Only 1 organization and 2 buckets')

                self.assertEqual(6,
                                 len(self.reduced_inventory(session,
                                                            inventory_index_id,
                                                            [])),
                                 'No types should yield empty list')

        with scoped_sessionmaker() as session:
            storage = Storage(session, self.engine)
            _ = storage.open()
            for resource in resources:
                storage.write(resource)
            storage.commit()
            inventory_index_id = storage.inventory_index.id
            self.assertEqual(3,
                             len(self.reduced_inventory(
                                 session,
                                 inventory_index_id,
                                 ['organization', 'bucket'])),
                             'Only 1 organization and 2 buckets')

            self.assertEqual(6,
                             len(self.reduced_inventory(session,
                                                        inventory_index_id,
                                                        [])),
                             'No types should yield empty list')


    def test_storage_with_timestamps(self):
        """Crawl from project, verify every resource has a timestamp."""

        def verify_resource_timestamps_from_storage(storage):
            session = storage.session
            inventory_index_id = storage.inventory_index.id
            for i, item in enumerate(DataAccess.iter(session,
                                                     inventory_index_id,
                                                     list()),
                                     start=1):
                self.assertTrue('timestamp' in item.get_other())
            return i

        initialize(self.engine)
        scoped_sessionmaker = db.create_scoped_sessionmaker(self.engine)

        res_org = ResourceMock('1', {'id': 'test'}, 'organization', 'resource')
        with scoped_sessionmaker() as session:
            with Storage(session, self.engine) as storage:
                storage.write(res_org)
                storage.commit()

                resource_count = (
                    verify_resource_timestamps_from_storage(storage))
                self.assertEqual(1, resource_count,
                                 'Unexpected number of resources in inventory')

    def test_whether_resource_should_be_inserted_or_skipped(self):
        """Whether the resource should be inserted or skipped.

        All resources should not be written if they have been previously
        written. Except group members, where members can be in multiple groups.
        """

        initialize(self.engine)
        scoped_sessionmaker = db.create_scoped_sessionmaker(self.engine)

        res_org = ResourceMock('1', {'id': 'test'}, 'organization', 'resource')
        res_proj1 = ResourceMock('2', {'id': 'test'}, 'project', 'resource',
                                 res_org)
        res_proj1.set_iam_policy({'id': 'test'})
        res_proj1.set_billing_info({'id': 'test'})
        res_buc1 = ResourceMock('5', {'id': 'test'}, 'bucket', 'resource',
                                res_org)
        res_proj2 = ResourceMock('6', {'id': 'test'}, 'project', 'resource',
                                 res_org)
        res_buc2 = ResourceMock('7', {'id': 'test'}, 'bucket', 'resource',
                                res_proj2)
        res_obj2 = ResourceMock('8', {'id': 'test'}, 'object', 'resource',
                                res_buc2)
        res_group1 =  ResourceMock('9', {'id': 'test'}, 'google_group',
                                   'resource', res_org)
        res_group2 =  ResourceMock('10', {'id': 'test'}, 'google_group',
                                   'resource', res_org)
        res_group_member1 = ResourceMock('11', {'id': 'user111',
                                         'kind': 'admin#directory#member'},
                                         'gsuite_group_member',
                                         'resource', res_group1)
        res_group_member2 = ResourceMock('11', {'id': 'user111',
                                         'kind': 'admin#directory#member'},
                                         'gsuite_group_member',
                                         'resource', res_group2)
        res_group_member3 = ResourceMock('12', {'id': 'user222',
                                         'kind': 'admin#directory#member'},
                                         'gsuite_group_member',
                                         'resource', res_group1)
        res_proj3 = ResourceMock('6', {'id': 'dup_proj'}, 'project',
                                 'resource', res_org)

        resources = [
            res_org,
            res_proj1,
            res_buc1,
            res_proj2,
            res_buc2,
            res_obj2,
            res_proj3,
            res_group1,
            res_group2,
            res_group_member1,
            res_group_member2,
            res_group_member3
        ]

        with scoped_sessionmaker() as session:
            with Storage(session, self.engine) as storage:
                for resource in resources:
                    storage.write(resource)
                storage.commit()

                inventory_index_id = storage.inventory_index.id
                self.assertEqual(3,
                                 len(self.reduced_inventory(
                                     session,
                                     inventory_index_id,
                                     ['organization', 'project'])),
                                 'Only 1 organization and 2 unique projects')

                self.assertEqual(3,
                                 len(self.reduced_inventory(
                                     session,
                                     inventory_index_id,
                                     ['gsuite_group_member'])),
                                 'All group members should be stored.')

                self.assertEqual(11,
                                 len(self.reduced_inventory(
                                     session,
                                     inventory_index_id,
                                     [])),
                                 'No types should yield empty list')


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
        res_proj1.set_iam_policy({'id': 'test'})
        res_proj1.set_billing_info({'id': 'test'})
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

        storage = Storage(self.session, self.engine)
        inv_index_id = storage.open()
        for resource in resources:
            storage.write(resource)
        storage.commit()
        # add more resource data that belongs to a different inventory index
        storage = Storage(self.session, self.engine)
        storage.open()
        for resource in resources:
            storage.write(resource)
        storage.commit()

        inv_index = self.session.query(InventoryIndex).get(inv_index_id)
        expected = {'bucket': 2, 'object': 1, 'organization': 1, 'project': 2}
        inv_summary = inv_index.get_summary(self.session)
        self.assertEqual(expected, inv_summary)

    @unittest.skip('The return value for query.all will leak to other tests.')
    def test_get_lifecycle_state_details_can_handle_none_result(self):
        mock_session = mock.MagicMock
        mock_session.query = mock.MagicMock
        mock_session.query.filter = mock.MagicMock
        mock_session.query.group_by = mock.MagicMock
        mock_session.query.all = mock.MagicMock
        mock_session.query.all.return_value = [None]

        inventory_index = InventoryIndex()
        details = inventory_index.get_lifecycle_state_details(mock_session,
                                                              'abc')

        self.assertEqual({}, details)


if __name__ == '__main__':
    unittest.main()
