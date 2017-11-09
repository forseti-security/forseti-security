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

""" Unit Tests: Importer for IAM Explain. """

import mock
import unittest

from tests.unittest_utils import ForsetiTestCase
from google.cloud.forseti.services.utils import autoclose_stream, logcall


class IamUtilsTest(ForsetiTestCase):
    """Test IAM utils."""

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

if __name__ == '__main__':
    unittest.main()
