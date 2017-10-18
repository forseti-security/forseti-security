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

""" Inventory API. """

# TODO: Remove this when time allows
# pylint: disable=missing-type-doc,missing-return-type-doc,missing-return-doc
# pylint: disable=missing-param-doc,line-too-long,broad-except
# pylint: disable=invalid-name

from Queue import Queue

from google.cloud.security.common.storage.sql_storage import DataAccess
from google.cloud.security.common.storage.sql_storage import initialize as init_storage
from google.cloud.security.inventory.crawler import run_crawler


class Progress(object):
    """Progress state."""

    def __init__(self, final_message=False, step="", inventory_id=-1):
        self.inventory_id = inventory_id
        self.final_message = final_message
        self.step = step
        self.warnings = 0
        self.errors = 0
        self.last_warning = ""
        self.last_error = ""


class QueueProgresser(Progress):
    """Queue based progresser."""

    def __init__(self, queue):
        super(QueueProgresser, self).__init__()
        self.queue = queue

    def _notify(self):
        """Notify status update into queue."""

        self.queue.put_nowait(self)

    def _notify_eof(self):
        """Notify end of status updates into queue."""

        self.queue.put(None)

    def on_new_object(self, resource):
        """Update the status with the new resource."""

        self.step = resource.key()
        self._notify()

    def on_warning(self, warning):
        """Stores the warning and updates the counter."""

        self.last_warning = warning
        self.warnings += 1
        self._notify()

    def on_error(self, error):
        """Stores the error and updates the counter."""

        self.last_error = error
        self.errors += 1
        self._notify()

    def get_summary(self):
        """Indicate end of updates, and return self as last state.

        Returns:
            object: Progresser in its last state.
        """

        self.final_message = True
        self._notify()
        self._notify_eof()
        return self


class FirstMessageQueueProgresser(QueueProgresser):
    """Queue base progresser only delivers first message.
    Then throws away all subsequent messages. This is used
    to make sure that we're not creating an internal buffer of
    infinite size as we're crawling in background without a queue consumer."""

    def __init__(self, *args, **kwargs):
        super(FirstMessageQueueProgresser, self).__init__(*args, **kwargs)
        self.first_message_sent = False

    def _notify(self):
        if not self.first_message_sent:
            self.first_message_sent = True
            QueueProgresser._notify(self)

    def _notify_eof(self):
        if not self.first_message_sent:
            self.first_message_sent = True
        QueueProgresser._notify_eof(self)


def run_inventory(service_config,
                  queue,
                  session,
                  progresser,
                  background):
    """Runs the inventory given the environment configuration.

    Args:
        service_config (object): Service configuration.
        queue (object): Queue to push status updates into.
        session (object): Database session.
        progresser (object): Progresser implementation to use.

    Returns:
        object: Returns the result of the crawl.

    Raises:
        Exception: Reraises any exception.
    """

    storage_cls = service_config.get_storage_class()
    with storage_cls(session) as storage:
        try:
            progresser.inventory_id = storage.index.id
            progresser.final_message = True if background else False
            queue.put(progresser)
            result = run_crawler(storage,
                                 progresser,
                                 service_config.get_inventory_config())
        except Exception:
            storage.rollback()
            raise
        else:
            storage.commit()
        return result


def run_import(client, model_name, inventory_id, background):
    """Runs the import against an inventory.

    Args:
        client (object): Api client to use.
        model_name (str): Model name to create.
        inventory_id (int): Inventory index number to source.
        background (bool): If the import should run in background.

    Returns:
        object: RPC response object to indicate status.
    """

    return client.explain.new_model('INVENTORY',
                                    model_name,
                                    inventory_id,
                                    background)


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

        Yields:
            object: Yields status updates.
        """

        queue = Queue()
        if background:
            progresser = FirstMessageQueueProgresser(queue)
        else:
            progresser = QueueProgresser(queue)

        def do_inventory():
            """Run the inventory."""

            with self.config.scoped_session() as session:
                try:
                    result = run_inventory(
                        self.config,
                        queue,
                        session,
                        progresser,
                        background)

                    if not model_name:
                        return result
                    return run_import(self.config.client(),
                                      model_name,
                                      result.inventory_id,
                                      background)
                except Exception as e:
                    queue.put(e)
                    queue.put(None)

        if background:
            self.config.run_in_background(do_inventory)
            yield queue.get()

        else:
            result = self.config.run_in_background(do_inventory)
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
