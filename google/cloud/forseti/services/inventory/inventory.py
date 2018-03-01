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

# pylint: disable=line-too-long,broad-except

from Queue import Queue

from google.cloud.forseti.services.inventory.storage import DataAccess
from google.cloud.forseti.services.inventory.storage import initialize as init_storage
from google.cloud.forseti.services.inventory.crawler import run_crawler


class Progress(object):
    """Progress state."""

    def __init__(self, final_message=False, step='', inventory_id=''):
        """Initialize

        Args:
            final_message (bool): whether it is the last message
            step (str): which step is this progress about
            inventory_id (str): The id of the inventory
        """
        self.inventory_id = inventory_id
        self.final_message = final_message
        self.step = step
        self.warnings = 0
        self.errors = 0
        self.last_warning = ''
        self.last_error = ''


class QueueProgresser(Progress):
    """Queue based progresser."""

    def __init__(self, queue):
        """Initialize

        Args:
            queue (Queue): progress queue to storage status
        """
        super(QueueProgresser, self).__init__()
        self.queue = queue

    def _notify(self):
        """Notify status update into queue."""

        self.queue.put_nowait(self)

    def _notify_eof(self):
        """Notify end of status updates into queue."""

        self.queue.put(None)

    def on_new_object(self, resource):
        """Update the status with the new resource.

        Args:
            resource (Resource): db row of Resource
        """

        self.step = resource.key()
        self._notify()

    def on_warning(self, warning):
        """Stores the warning and updates the counter.

        Args:
            warning (str): warning message
        """

        self.last_warning = warning
        self.warnings += 1
        self._notify()

    def on_error(self, error):
        """Stores the error and updates the counter.

        Args:
            error (str): error message
        """

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
    """Queue base progresser

    Only delivers first message. Then throws away all subsequent messages.
    This is used to make sure that we're not creating an internal buffer of
    infinite size as we're crawling in background without a queue consumer.
    """

    def __init__(self, *args, **kwargs):
        """Initialize

        Args:
            *args (list): Arguments.
            **kwargs (dict): Arguments.
        """
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
        background (bool): whether to run the inventory in background

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
        inventory_id (str): Inventory index to source.
        background (bool): If the import should run in background.

    Returns:
        object: RPC response object to indicate status.
    """

    return client.model.new_model('INVENTORY',
                                  model_name,
                                  inventory_id,
                                  background)


class Inventory(object):
    """Inventory API implementation."""

    def __init__(self, config):
        """Initialize

        Args:
            config (object): ServiceConfig in server
        """
        self.config = config
        init_storage(self.config.get_engine())

    def create(self, background, model_name):
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
            """Run the inventory.

            Returns:
                object: inventory crawler result if no model_name specified,
                    otherwise, model import result
            """

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

    def list(self):
        """List stored inventory.

        Yields:
            object: Inventory metadata
        """

        with self.config.scoped_session() as session:
            for item in DataAccess.list(session):
                yield item

    def get(self, inventory_id):
        """Get inventory metadata by id.

        Args:
            inventory_id (str): Id of the inventory.

        Returns:
            object: Inventory metadata
        """

        with self.config.scoped_session() as session:
            result = DataAccess.get(session, inventory_id)
            return result

    def delete(self, inventory_id):
        """Delete an inventory by id.

        Args:
            inventory_id (str): Id of the inventory.

        Returns:
            object: Inventory object that was deleted
        """

        with self.config.scoped_session() as session:
            result = DataAccess.delete(session, inventory_id)
            return result
