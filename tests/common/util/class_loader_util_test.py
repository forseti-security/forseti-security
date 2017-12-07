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

"""Tests the class loader utility."""

import unittest
import mock

from tests.unittest_utils import ForsetiTestCase
from google.cloud.forseti.common.util import class_loader_util


class ClassLoaderUtilTest(ForsetiTestCase):
    """Test the class loader utility."""

    def test_dne_module_load_fails(self):
        """Test that a module that does not exist fails."""
        with self.assertRaises(class_loader_util.InvalidForsetiClassError):
            class_loader_util.load_class('fake.class.dne')

    def test_dne_class_load_fails(self):
        """Test that a class that does not exist fails."""
        with self.assertRaises(class_loader_util.InvalidForsetiClassError):
            class_loader_util.load_class('google.cloud.forseti.FakeClass')


if __name__ == '__main__':
    unittest.main()
