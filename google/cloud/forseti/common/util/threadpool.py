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

""" Thread pool implementation for async job distribution. """

from Queue import Queue
from threading import Thread
from threading import Lock

from google.cloud.forseti.common.util import logger


LOGGER = logger.get_logger(__name__)


class Worker(Thread):
    """Thread executing callables from queue."""

    def __init__(self, queue):
        """Initalize.

        Args:
            queue (Queue): A queue.
        """
        Thread.__init__(self)
        self.queue = queue
        self.daemon = True
        self.start()

    # pylint: disable=broad-except
    def run(self):
        """Run the worker."""
        while True:
            func, args, kargs, result = self.queue.get()
            try:
                val = func(*args, **kargs)
                result.put(val, False)
            except Exception as e:
                LOGGER.exception(e)
                result.put(e, True)
            finally:
                self.queue.task_done()


class Result(object):
    """Used to communicate job result values and exceptions."""

    def __init__(self):
        """Initialize."""
        self.lock = Lock()
        self.lock.acquire()
        self.value = Exception()
        self.raised = False

    def put(self, value, raised):
        """Worker puts value or exception into result.

        Args:
            value (object): A value or exception.
            raised (bool): Whether exception was raised.
        """
        self.value = value
        self.raised = raised
        self.lock.release()

    def get(self):
        """Get value after worker has completed.

        Returns:
            object: The value.
        """
        self.lock.acquire()
        try:
            if self.raised:
                raise self.value
            return self.value
        finally:
            self.lock.release()


class ThreadPool(object):
    """ThreadPool consumes tasks via queue."""

    def __init__(self, num_workers):
        """Initialize.

        Args:
            num_workers (int): The number of workers.
        """
        self.queue = Queue(num_workers)
        self.workers = []
        for _ in range(num_workers):
            self.workers.append(Worker(self.queue))

    def add_func(self, func, *args, **kargs):
        """Add a callable to the queue.

        Args:
            func (function): A callable.
            *args (list): Non-keyworded variable args.
            **kargs (dict): Keyworded variable args.

        Returns:
            Result: The result.
        """
        result = Result()
        self.queue.put((func, args, kargs, result))
        return result

    def join(self):
        """Returns after completion of all pending callables."""
        self.queue.join()
