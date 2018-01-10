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

"""Test Forseti Auditor."""

import unittest

from tests.services.api_test.inventory_test import TestServiceConfig
from tests.services.inventory.crawling_test import NullProgresser
from tests.unittest_utils import ForsetiTestCase

from google.cloud.forseti.services.auditor import auditor as auditor_api

class AuditorTest(ForsetiTestCase):
    """Test Auditor."""

    def setUp(self):
        """setUp."""
        self.config = TestServiceConfig()
        self.auditor = auditor_api.Auditor(self.config)
        self.progresser = NullProgresser()

    def test_run_audit(self):
        """Test run_audit()."""

