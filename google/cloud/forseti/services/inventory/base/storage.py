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

""" Crawler implementation. """

from google.cloud.forseti.common.util import date_time
from google.cloud.forseti.common.util import string_formats

# pylint: disable=invalid-name


class Storage(object):
    """The inventory storage interface"""

    def open(self, handle=None):
        """Not Implemented.

        Args:
            handle (str): If None, create a new index instead
                of opening an existing one.

        Raises:
            NotImplementedError: Because not implemented.
        """
        raise NotImplementedError()

    def write(self, resource):
        """Not Implemented.

        Args:
            resource (object): the resource object to write

        Raises:
            NotImplementedError: Because not implemented.
        """
        raise NotImplementedError()

    def update(self, resource):
        """Not Implemented.

        Args:
            resource (object): the resource object to update

        Raises:
            NotImplementedError: Because not implemented.
        """
        raise NotImplementedError()

    def error(self, message):
        """Not Implemented.

        Args:
            message (str): Error message describing the problem.

        Raises:
            NotImplementedError: Because not implemented.
        """
        raise NotImplementedError()

    def warning(self, message):
        """Not Implemented.

        Args:
            message (str): Warning message describing the problem.

        Raises:
            NotImplementedError: Because not implemented.
        """
        raise NotImplementedError()

    def close(self):
        """Not Implemented.

        Raises:
            NotImplementedError: Because not implemented.
        """
        raise NotImplementedError()

    def commit(self):
        """Not Implemented.

        Raises:
            NotImplementedError: Because not implemented.
        """
        raise NotImplementedError()

    def rollback(self):
        """Not Implemented.

        Raises:
            NotImplementedError: Because not implemented.
        """
        raise NotImplementedError()


class Memory(Storage):
    """The storage in memory"""

    def __init__(self, session=None):
        """Initialize.

        Args:
            session (object): An optional session for inventory cache.
        """
        super(Memory, self).__init__()
        self.mem = {}
        self.session = session

    def open(self, handle=None):
        """Open the memory storage

        Args:
            handle (str): If None, create a new index instead
                of opening an existing one.

        Returns:
            str: inventory index
        """
        if handle:
            handle = handle
        else:
            handle = date_time.get_utc_now_datetime().strftime(
                string_formats.TIMESTAMP_MICROS
            )
        return handle

    def write(self, resource):
        """Write a resource object into storage

        Args:
            resource (object): the resource object to write
        """
        self.mem[resource.type() + resource.key()] = resource

    def update(self, resource):
        """Update a existing resource object in memory

        Args:
            resource (object): the resource object to update
        """
        pass

    def read(self, key):
        """Read a resource object from storage

        Args:
            key (str): key of the resource object

        Returns:
            object: the resource object being read
        """
        return self.mem[key]

    def error(self, message):
        """Ignore the error message

        Args:
            message (str): Error message describing the problem.
        """
        pass

    def warning(self, message):
        """Ignore the warning message

        Args:
            message (str): Warning message describing the problem.
        """
        pass

    def close(self):
        """close the memory storage"""
        pass

    def __enter__(self):
        """To support with statement for auto closing.

        Returns:
            Storage: The memory storage object
        """
        self.open()
        return self

    def __exit__(self, type_p, value, tb):
        """To support with statement for auto closing.

        Args:
            type_p (object): Unused.
            value (object): Unused.
            tb (object): Unused.
        """
        self.close()

    def commit(self):
        """No need to commit when using a memory storage"""
        pass

    def rollback(self):
        """No rollback when using a memory storage"""
        pass
