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
"""test for delay.py."""

import time
import unittest
import google.apputils
from mock import Mock, patch
from tests import unittest_utils
from google.cloud.security.common.util import delay


class DelayTest(unittest_utils.ForsetiTestCase):
    """ Tests for the Delay Utility."""

    def delay_test(self):
        """test to verify that a delay is used"""
        delay_by = 9
        param = 1
        wait_function = Mock()
        inside_function = Mock()

        @delay.delay(delay_by, clock=wait_function)
        def function_test():
            inside_function(func)
            return func

        result = function_test(param)
        inside_function.assert_called_once_with(param)
        self.assertEqual(result, param)
        waitfunc.assert_called_once_with(delay_by)


if __name__ == '__main__':
    unittest.main()
