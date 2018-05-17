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

"""Tests for install/gcp/installer/util/utils.py."""

import unittest

import install.gcp.installer.util.utils as utils

from tests.unittest_utils import ForsetiTestCase


class UtilsTest(ForsetiTestCase):

    def test_id_from_name_normal(self):
        """The name of the resource, formatted as
        ${RESOURCE_TYPE}/${RESOURCE_ID}, make ${RESOURCE_ID} is returned."""
        test_name = 'RESOURCE_TYPE/RESOURCE_ID'
        expected_name = 'RESOURCE_ID'
        self.assertTrue(utils.id_from_name(test_name), expected_name)

    def test_id_from_name_multiple_backslashes(self):
        """The name of the resource, formatted as
        ${RESOURCE_TYPE}/${RESOURCE_ID}, make ${RESOURCE_ID} is returned."""
        test_name = 'RESOURCE_TYPE1/RESOUCE_TYPE2/RESOURCE_TYPE3/RESOURCE_ID'
        expected_name = 'RESOURCE_ID'
        self.assertTrue(utils.id_from_name(test_name), expected_name)

    def test_id_from_name_no_backslash(self):
        """The name of the resource, formatted as
        ${RESOURCE_TYPE}/${RESOURCE_ID}, make ${RESOURCE_ID} is returned."""
        test_name = 'RESOURCE_ID'
        expected_name = 'RESOURCE_ID'
        self.assertTrue(utils.id_from_name(test_name), expected_name)

    def test_sanitize_conf_values_normal_input(self):
        """Normal config values."""
        input_conf = {
            'apple': '12',
            'orange': '5',
            'banana': ''
        }
        expected_conf = {
            'apple': '12',
            'orange': '5',
            'banana': '""'
        }
        self.assertEquals(
            utils.sanitize_conf_values(input_conf), expected_conf)

    def test_sanitize_conf_values_empty_input(self):
        """empty config values."""
        input_conf = {}
        expected_conf = {}
        self.assertEquals(
            utils.sanitize_conf_values(input_conf), expected_conf)


if __name__ == '__main__':
    unittest.main()
