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

"""Tests the Logging utility."""
import logging
import unittest

from tests.unittest_utils import ForsetiTestCase
from google.cloud.forseti.common.util import logger


class LogUtilTest(ForsetiTestCase):
    """Test the Logging utility."""

    def setUp(self):
        """Test with default log level of info."""
        self.current_level = logger.LOGLEVEL
        logger.set_logger_level(logging.INFO)

    def tearDown(self):
        """Reset log level on all loggers."""
        logger.set_logger_level(self.current_level)

    def test_set_logger_level_changes_existing_loggers(self):
        """Test if loggers instantiated before set_logger_level will be affected."""

        previous_logger = logger.get_logger('test_module_1')
        self.assertEqual(previous_logger.level, logging.INFO, 'Expecting default level to be info')
        logger.set_logger_level(logging.ERROR)
        self.assertEqual(previous_logger.level, logging.ERROR, 'Level should have changed to ERROR')
        logger.set_logger_level(logging.INFO)
        self.assertEqual(previous_logger.level, logging.INFO, 'Level should have changed back to INFO')

    def test_set_logger_level_changes_future_loggers(self):
        """Test if loggers instantiated after set_logger_level will be affected."""

        previous_logger = logger.get_logger('test_module_2')
        self.assertEqual(previous_logger.level, logging.INFO, 'Expecting default level to be info')
        logger.set_logger_level(logging.ERROR)
        future_logger = logger.get_logger('test_module_3')
        self.assertEqual(future_logger.level, logging.ERROR, 'Level should have changed to ERROR')
        logger.set_logger_level(logging.INFO)
        self.assertEqual(previous_logger.level, logging.INFO, 'Level should have changed back to INFO')

    def test_set_logger_level_from_config(self):
        """Test that a config value for logger sets the correct logger level."""
        previous_logger = logger.get_logger('test_module_4')
        self.assertEqual(previous_logger.level, logging.INFO,
            'Default loglevel should be INFO')
        logger.set_logger_level_from_config('debug')
        future_logger = logger.get_logger('test_module_5')
        self.assertEqual(future_logger.level, logging.DEBUG,
            'Next loglevel should be DEBUG')
        logger.set_logger_level_from_config('junk')
        self.assertEqual(previous_logger.level, logging.DEBUG,
            'Level should have remained DEBUG')


if __name__ == '__main__':
    unittest.main()
