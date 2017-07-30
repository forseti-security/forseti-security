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

""" Crawler implementation. """

from collections import defaultdict


class Storage(object):

    def open(self):
        raise NotImplementedError()

    def write(self, resource):
        raise NotImplementedError()

    def read(self, resource_key):
        raise NotImplementedError()

    def error(self, exception):
        raise NotImplementedError()

    def warning(self, exception):
        raise NotImplementedError()

    def close(self):
        raise NotImplementedError()


class Memory(Storage):
    HANDLE = 0

    def __init__(self):
        super(Memory, self).__init__()
        self.mem = {}

    def open(self):
        handle = self.HANDLE
        self.HANDLE += 1
        return handle

    def write(self, resource):
        self.mem[resource.key()] = resource

    def read(self, resource_key):
        return self.mem[resource_key]

    def error(self, exception):
        pass

    def warning(self, exception):
        pass

    def close(self):
        pass
