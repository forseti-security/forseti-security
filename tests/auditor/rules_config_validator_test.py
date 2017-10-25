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

"""Rules Config Validator tests."""

import mock
import unittest
import MySQLdb

from google.cloud.security.auditor import rules_config_validator
from tests.unittest_utils import ForsetiTestCase


class RulesConfigValidator(ForsetiTestCase):

    def setUp(self):
        self.validator = rules_config_validator.RulesConfigValidator

    def test_check_unmatched_config_vars(self):
        """Test _check_unmatched_config_vars()."""
        pass

    def test_check_invalid_conditions(self):
        """Test _check_invalid_conditions()."""
        pass

    def test_validate(self):
        """Test validate()."""
        pass


if __name__ == '__main__':
    unittest.main()
