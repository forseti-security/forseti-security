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

""" Inventory API. """

# TODO: The next editor must remove this disable and correct issues.
# pylint: disable=missing-type-doc,missing-return-type-doc,missing-return-doc
# pylint: disable=missing-param-doc

from google.cloud.security.iam.inventory.storage import DataAccess
from google.cloud.security.common.util.threadpool import ThreadPool


# pylint: disable=invalid-name,no-self-use
class Inventory(object):
    """Inventory API implementation."""

    def __init__(self, config):
        self.config = config

    def Create(self, background, model_name):
        """Create a new inventory,

        Args:
            background (bool): Run import in background, return immediately
            model_name (str): Model name to import into
        """

        with self.config.session() as session:
            def run_inventory():
                pass
            workers = ThreadPool(1)
            workers.add_func(run_inventory)
            pass

    def List(self):
        """List stored inventory.

        Yields:
            object: Inventory metadata
        """

        with self.config.session() as session:
            for item in DataAccess.list(session):
                yield item

    def Get(self, inventory_id):
        """Get inventory metadata by id.

        Args:
            inventory_id (int): Id of the inventory.

        Returns:
            object: Inventory metadata
        """

        with self.config.session() as session:
            return DataAccess.get(session, inventory_id)

    def Delete(self, inventory_id):
        """Delete an inventory by id.

        Args:
            inventory_id (int): Id of the inventory.

        Returns:
            object: Inventory object that was deleted
        """

        with self.config.session() as session:
            return DataAccess.delete(session, inventory_id)
