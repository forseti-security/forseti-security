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

"""Resource Node Tests."""

import unittest

from tests.resource_node import ResourceNode


class TestResourceNode(unittest.TestCase):
    """Test resource node."""

    def test_node_equals_simple(self):
        a = ResourceNode('a', 'l1')
        b = ResourceNode('b', 'l1')
        self.assertEqual(a, b)

    def test_node_equals_nested(self):
        a = ResourceNode('a', 'l1')
        a.children = [ResourceNode('c', 'l2')]
        b = ResourceNode('b', 'l1')
        b.children = [ResourceNode('d', 'l2')]
        self.assertEqual(a, b)

    def test_node_equals_nested_unsorted(self):
        a = ResourceNode('a', 'l1')
        a.children = [ResourceNode('c', 'l2'), ResourceNode('k', 'l2-1')]
        b = ResourceNode('b', 'l1')
        b.children = [ResourceNode('q', 'l2-1'), ResourceNode('d', 'l2')]
        self.assertEqual(a, b)

    def test_node_not_equals_simple(self):
        a = ResourceNode('a', 'l1')
        b = ResourceNode('a', 'l2')
        self.assertNotEqual(a, b)

    def test_node_not_equals_nested(self):
        a = ResourceNode('a', 'l1')
        a.children = [ResourceNode('c', 'l2')]
        b = ResourceNode('b', 'l1-1')
        b.children = [ResourceNode('d', 'l2')]
        self.assertNotEqual(a, b)

    def test_node_children_not_equals_nested(self):
        a = ResourceNode('a', 'l1')
        a.children = [ResourceNode('c', 'l2')]
        b = ResourceNode('b', 'l1')
        b.children = [ResourceNode('d', 'l3')]
        self.assertNotEqual(a, b)

    def test_node_not_equals_nested_multiple_child(self):
        a = ResourceNode('a', 'l1')
        a.children = [ResourceNode('c', 'l2'), ResourceNode('k', 'l2-1')]
        b = ResourceNode('b', 'l1')
        b.children = [ResourceNode('q', 'l2-1'), ResourceNode('d', 'l2-2')]
        self.assertNotEqual(a, b)
