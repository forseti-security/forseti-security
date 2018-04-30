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
"""Unit Tests: Purge inventory for Forseti Server."""

from datetime import datetime
import mock
import unittest

from tests.services.util.db import create_test_engine
from tests.unittest_utils import ForsetiTestCase

from google.cloud.forseti.services import db
from google.cloud.forseti.services.inventory.inventory import Inventory as InventoryApi
from google.cloud.forseti.services.inventory.storage import initialize
from google.cloud.forseti.services.inventory.storage import Inventory
from google.cloud.forseti.services.inventory.storage import InventoryIndex


class PurgeInventoryTest(ForsetiTestCase):
    """Test purging the inventory."""

    def setUp(self):
        """Setup method."""
        ForsetiTestCase.setUp(self)

    def tearDown(self):
        """Tear down method."""
        ForsetiTestCase.tearDown(self)

    def populate_data(self):
        self.engine = create_test_engine()
        initialize(self.engine)
        self.scoped_sessionmaker = db.create_scoped_sessionmaker(self.engine)

        with self.scoped_sessionmaker() as session:
            inventory_indices = [
                InventoryIndex(
                    id='one_day_old',
                    created_at_datetime=datetime(2010, 12, 30, 8, 0, 0)
                ),
                InventoryIndex(
                    id='seven_days_old',
                    created_at_datetime=datetime(2010, 12, 24, 8, 0, 0)
                ),
                InventoryIndex(
                    id='nine_days_old',
                    created_at_datetime=datetime(2010, 12, 22, 8, 0, 0)
                )
            ]
            for i in inventory_indices:
                session.add(i)
            session.commit()
            session.expunge_all()
            
            inventory_resources = [
                Inventory(
                    id=1,
                    inventory_index_id='one_day_old'),
                Inventory(
                    id=2,
                    inventory_index_id='one_day_old'),
                Inventory(
                    id=3,
                    inventory_index_id='seven_days_old'),
                Inventory(
                    id=4,
                    inventory_index_id='seven_days_old'),
                Inventory(
                    id=5,
                    inventory_index_id='nine_days_old'),
                Inventory(
                    id=6,
                    inventory_index_id='nine_days_old'),
            ]
            for i in inventory_resources:
                session.add(i)
            session.commit()
            session.expunge_all()
            
        return session      

    def get_inventory_api(self):

        mock_config = mock.MagicMock()
        mock_config.get_engine.return_value = self.engine
        mock_config.scoped_session.return_value = self.scoped_sessionmaker()

        return InventoryApi(mock_config)

    @mock.patch(
        'google.cloud.forseti.services.inventory.inventory.date_time',
        autospec=True)
    def test_all_inventory_are_purged(self, mock_date_time):
        """Test all inventory are purged."""

        session = self.populate_data()
        mock_date_time.get_utc_now_datetime.return_value = (
            datetime(2010, 12, 31))

        inventory_api = self.get_inventory_api()
        inventory_api.purge(retention_days='0')

        inventory_indices = session.query(InventoryIndex).all()
        self.assertEquals(0, len(inventory_indices))

        resources = session.query(Inventory).all()
        self.assertEquals(0, len(resources))

    @mock.patch(
        'google.cloud.forseti.services.inventory.inventory.date_time',
        autospec=True)
    def test_purge_is_disabled(self, mock_date_time):
        """Test purge is disabled."""

        session = self.populate_data()
        mock_date_time.get_utc_now_datetime.return_value = (
            datetime(2010, 12, 31))

        inventory_api = self.get_inventory_api()
        inventory_api.purge(retention_days='-1')

        inventory_indices = session.query(InventoryIndex).all()
        self.assertEquals(3, len(inventory_indices))

        resources = session.query(Inventory).all()
        self.assertEquals(6, len(resources))


    @mock.patch(
        'google.cloud.forseti.services.inventory.inventory.date_time',
        autospec=True)
    def test_purge_uses_configuration_value(self, mock_date_time):
        """Test purge uses configuration value."""

        session = self.populate_data()
        mock_date_time.get_utc_now_datetime.return_value = (
            datetime(2010, 12, 31))

        inventory_api = self.get_inventory_api()
        inventory_api.config.inventory_config.retention_days = -1
        inventory_api.purge(retention_days=None)

        inventory_indices = session.query(InventoryIndex).all()
        self.assertEquals(3, len(inventory_indices))

        resources = session.query(Inventory).all()
        self.assertEquals(6, len(resources))

    @mock.patch(
        'google.cloud.forseti.services.inventory.inventory.date_time',
        autospec=True)
    def test_no_inventory_is_purged(
            self, mock_date_time):
        """Test no inventory is purged.
        
        In this case, there are no inventory older than the retention_days.
        """

        session = self.populate_data()
        mock_date_time.get_utc_now_datetime.return_value = (
            datetime(2010, 12, 31))

        inventory_api = self.get_inventory_api()
        inventory_api.purge(retention_days='30')

        inventory_indices = session.query(InventoryIndex).all()
        self.assertEquals(3, len(inventory_indices))

        resources = session.query(Inventory).all()
        self.assertEquals(6, len(resources))

    @mock.patch(
        'google.cloud.forseti.services.inventory.inventory.date_time',
        autospec=True)
    def test_inventory_older_than_retention_days_are_purged(
            self, mock_date_time):
        """Test inventory older than retention_days are purged."""

        session = self.populate_data()
        mock_date_time.get_utc_now_datetime.return_value = (
            datetime(2010, 12, 31))

        inventory_api = self.get_inventory_api()
        inventory_api.purge(retention_days='5')
       
        inventory_indices = session.query(InventoryIndex).all()
        self.assertEquals(1, len(inventory_indices))
        for i in inventory_indices:
            self.assertEquals('one_day_old', i.id)

        resources = session.query(Inventory).all()
        self.assertEquals(2, len(resources))
        for i in resources:
            self.assertEquals('one_day_old', i.inventory_index_id)


if __name__ == '__main__':
    unittest.main()
