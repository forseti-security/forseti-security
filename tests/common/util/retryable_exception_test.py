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
"""Tests for google.cloud.forseti.common.util.retryable_exceptions."""

import unittest.mock as mock
from googleapiclient import http

from google.cloud.forseti.common.util import retryable_exceptions
from tests import unittest_utils


class RetryTest(unittest_utils.ForsetiTestCase):
    """Tests for the exceptions captured in the retry."""

    def test_resource_exhausted_captured(self):
        """Test to make sure resource exhausted error is being
        captured to retry.
        """
        error = http.HttpError(mock.Mock(status=429),
                               'Resource Exhausted'.encode())
        self.assertTrue(retryable_exceptions.is_retryable_exception(error))
