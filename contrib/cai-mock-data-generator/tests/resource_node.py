# Copyright 2019 The Forseti Security Authors. All rights reserved.
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

"""Resource Node Class."""

import hashlib


class ResourceNode(object):
    def __init__(self, resource_name, resource_type):
        self.resource_name = resource_name
        self.resource_type = resource_type
        self.children = []

    def __eq__(self, other):
        """Check for resource type equality.
        2 resource nodes are equal iff
            1. Their resource types are the same.
            2. Their child resource node are the same.
        """
        if (self.resource_type == other.resource_type and
                self.children == other.children):
            return True
        elif (self.resource_type == other.resource_type and
              len(self.children) == len(other.children)):
            self.children.sort()
            other.children.sort()
            for i in range(len(self.children)):
                is_child_same = self.children[i] == other.children[i]
                if not is_child_same:
                    return False
            return True
        return False

    def __lt__(self, other):
        """Sort by resource type."""
        return self.resource_type > other.resource_type

    def __hash__(self):
        return int(hashlib.md5(self.resource_name.encode()).hexdigest(), 16)
