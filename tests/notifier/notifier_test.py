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
"""Tests the notifier module."""

from datetime import datetime
import mock

from google.cloud.forseti.notifier import notifier
from tests.unittest_utils import ForsetiTestCase

class NotifierTest(ForsetiTestCase):

    def setUp(self):
        pass

    def test_can_convert_created_at_datetime_to_timestamp_string(self):
        violations = [
            mock.MagicMock(created_at_datetime=datetime(1999, 12, 25, 1, 2, 3)),
            mock.MagicMock(created_at_datetime=datetime(2010, 6, 8, 4, 5, 6))
        ]

        expected_timestamps = ['1999-12-25T01:02:03Z',
                               '2010-06-08T04:05:06Z']

        violations_with_converted_timestamp = (
            notifier.convert_to_timestamp(violations))
        
        converted_timestamps = []
        for i in violations_with_converted_timestamp:
            converted_timestamps.append(i.created_at_datetime)

        self.assertEquals(expected_timestamps,
                          converted_timestamps)
