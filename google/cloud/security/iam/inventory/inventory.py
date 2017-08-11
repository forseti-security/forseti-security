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

from Queue import Queue

from google.cloud.security.iam.inventory.storage import Storage
from google.cloud.security.iam.inventory.storage import DataAccess
from google.cloud.security.iam.inventory.storage import initialize as init_storage
from google.cloud.security.iam.inventory.crawler import run_crawler
from google.cloud.security.inventory2.progress import Progresser as BaseProgresser


class Progress(object):
    """Progress state."""

    def __init__(self, final_message=False, step=""):
        self.inventory_id = -1
        self.final_message = final_message
        self.step = step
        self.warnings = 0
        self.errors = 0
        self.last_warning = ""
        self.last_error = ""


class NullProgresser(BaseProgresser):
    """No-op progresser."""

    def __init__(self):
        pass

    def on_new_object(self, resource):
        pass

    def on_warning(self, warning):
        pass

    def on_error(self, error):
        pass

    def get_summary(self):
        pass


class QueueProgresser(Progress):
    def __init__(self, queue):
        super(QueueProgresser, self).__init__()
        self.queue = queue

    def _notify(self):
        self.queue.put(self, block=True, timeout=10)

    def on_new_object(self, resource):
        self.step = resource.key()
        self._notify()

    def on_warning(self, warning):
        self.last_warning = warning
        self.warnings += 1
        self._notify()

    def on_error(self, error):
        self.last_error = error
        self.errors += 1
        self._notify()

    def get_summary(self):
        self.final_message = True
        self._notify()
        self.queue.put(None)
        return self


def run_inventory(session, progresser):
    gsuite_sa = '/Users/fmatenaar/deployments/forseti/groups.json'
    with Storage(session) as storage:
        progresser.inventory_id = storage.index.id
        return run_crawler(storage, progresser, gsuite_sa)


def run_import(client, model_name):
    return client.explain('INVENTORY', model_name)


# pylint: disable=invalid-name,no-self-use
class Inventory(object):
    """Inventory API implementation."""

    def __init__(self, config):
        self.config = config
        init_storage(self.config.get_engine())

    def Create(self, background, model_name):
        """Create a new inventory,

        Args:
            background (bool): Run import in background, return immediately
            model_name (str): Model name to import into
        """

        queue = Queue()
        if background:
            progresser = NullProgresser()
        else:
            progresser = QueueProgresser(queue)

        def do_work():
            with self.config.scoped_session() as session:
                try:
                    result = run_inventory(session, progresser)
                    if not model_name:
                        return result
                    else:
                        return run_import(self.config.client(), model_name)
                except Exception as e:
                    queue.put(e)
                    queue.put(None)

        if background:
            self.config.run_in_background(do_work)
            yield Progress(True, 'Accepted')

        else:
            result = self.config.run_in_background(do_work)
            for progress in iter(queue.get, None):
                if isinstance(progress, Exception):
                    raise progress
                yield progress
            if result:
                yield result.get()

    def List(self):
        """List stored inventory.

        Yields:
            object: Inventory metadata
        """

        with self.config.scoped_session() as session:
            for item in DataAccess.list(session):
                yield item

    def Get(self, inventory_id):
        """Get inventory metadata by id.

        Args:
            inventory_id (int): Id of the inventory.

        Returns:
            object: Inventory metadata
        """

        with self.config.scoped_session() as session:
            result = DataAccess.get(session, inventory_id)
            return result

    def Delete(self, inventory_id):
        """Delete an inventory by id.

        Args:
            inventory_id (int): Id of the inventory.

        Returns:
            object: Inventory object that was deleted
        """

        with self.config.scoped_session() as session:
            result = DataAccess.delete(session, inventory_id)
            return result
