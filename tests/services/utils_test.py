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
"""Unit Tests: Importer for Forseti Server."""

import unittest
import mock
from tests.unittest_utils import ForsetiTestCase
from google.cloud.forseti.services.utils import autoclose_stream
from google.cloud.forseti.services.utils import get_resources_from_full_name
from google.cloud.forseti.services.utils import logcall
from google.cloud.forseti.services.utils import split_type_name
from google.cloud.forseti.services.utils import to_full_resource_name
from google.cloud.forseti.services.utils import to_type_name


class ServerUtilsTest(ForsetiTestCase):
    """Test Forseti Server util."""

    def test_autoclose_stream_decorator(self):
        """Test autoclose_stream wrapper."""

        @autoclose_stream
        def decorated(p1, p2, p3, context):
            for i in range(32):
                if i >= p1:
                    context._state.client = 'closed'
                yield i

        context = mock.Mock()
        context._state.client = 'connected'
        gen = decorated(5, None, None, context)
        self.assertEqual([0, 1, 2, 3, 4, 5],
                         [i for i in gen],
                         'Expecting 6 items to return')

    def test_logcall_decorator(self):
        """Test logcall wrapper."""

        @logcall
        def decorated(p1):
            return p1+1

        try:
            decorated(0)
        except Exception as e:
            self.fail(e.message)

    def test_to_full_resource_name(self):
        """Test to_full_resource_name."""

        self.assertEqual(
            to_full_resource_name('', 'foo/bar'),
            'foo/bar/')

        self.assertEqual(
            to_full_resource_name('foo/bar/', 'bar/baz'),
            'foo/bar/bar/baz/')

    def test_to_type_name(self):
        """Test to_type_name."""

        self.assertEqual(
            to_type_name('foo', 'bar'),
            'foo/bar')

    def test_split_type_name(self):
        """Test split_type_name."""

        self.assertEqual(
            split_type_name('foo/bar'),
            ['foo', 'bar'])

    def test_get_resources_from_full_name(self):
        """Test resources can be parsed from full name in reverse order."""

        fake_full_name = ('organization/org1/folder/folder2/folder/folder3/'
                          'project/project4/firewall/firewall5/')
        expected_resources = {
            0: ('firewall', 'firewall5'),
            1: ('project', 'project4'),
            2: ('folder', 'folder3'),
            3: ('folder', 'folder2'),
            4: ('organization', 'org1'),
        }

        resources = get_resources_from_full_name(fake_full_name)
        counter = 0
        for resource_type, resource_id in resources:
            self.assertEquals(expected_resources[counter],
                              (resource_type, resource_id))
            counter += 1


if __name__ == '__main__':
    unittest.main()
