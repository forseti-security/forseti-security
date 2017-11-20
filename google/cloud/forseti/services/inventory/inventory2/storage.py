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


# TODO: The next editor must remove this disable and correct issues.
# pylint: disable=missing-type-doc,missing-return-type-doc,missing-return-doc
# pylint: disable=missing-param-doc, invalid-name


class Storage(object):
    """The inventory storage interface"""

    def open(self, handle=None):
        """Not Implemented.

        Raises:
            NotImplementedError: Because not implemented.
        """
        raise NotImplementedError()

    def write(self, resource):
        """Not Implemented.

        Raises:
            NotImplementedError: Because not implemented.
        """
        raise NotImplementedError()

    def update(self, resource):
        """Not Implemented.

        Raises:
            NotImplementedError: Because not implemented.
        """
        raise NotImplementedError()

    def error(self, message):
        """Not Implemented.

        Raises:
            NotImplementedError: Because not implemented.
        """
        raise NotImplementedError()

    def warning(self, message):
        """Not Implemented.

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
    HANDLE = 0

    def __init__(self):
        super(Memory, self).__init__()
        self.mem = {}

    def open(self, handle=None):
        """Open the memory storage"""
        handle = self.HANDLE if handle is None else handle
        self.HANDLE += 1
        return handle

    def write(self, resource):
        """Write a resource object into storage"""
        self.mem[resource.key()] = resource

    def update(self, resource):
        """Update a existed resource object in memory"""
        pass

    def read(self, key):
        """Read a resource object from storage"""
        return self.mem[key]

    def error(self, message):
        """Ingore the error message"""
        pass

    def warning(self, message):
        """Ingore the warning message"""
        pass

    def close(self):
        """close the memory storage"""
        pass

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, type_p, value, tb):
        self.close()

    def commit(self):
        """No need to commit when using a memory storage"""
        pass

    def rollback(self):
        """No rollback when using a memory storage"""
        pass
