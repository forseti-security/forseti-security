# Copyright 2020 The Forseti Security Authors. All rights reserved.
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

"""Inventory performance end-to-end test"""

import pytest
import re
from sqlalchemy.sql import text


class TestConfigValidatorScan:
    """Config Validator Scan test

    Run a scan and assert CV scanner is run and there are no errors.
    """

    @pytest.mark.e2e
    @pytest.mark.scanner
    def test_cv_scan(self, forseti_scan_readonly):
        """Config Validator Scan test

        Args:
            forseti_scan_readonly (Tuple): Scanner id and scanner process result
        """
        # Arrange/Act
        scanner_id, scanner_result = forseti_scan_readonly

        # Assert scanner id
        assert scanner_id

        # Assert CV scanner was run
        regex = re.compile('Running ConfigValidatorScanner')
        match = regex.search(str(scanner_result.stdout))
        assert match

        # Assert scan completed
        regex = re.compile('Scan completed')
        match = regex.search(str(scanner_result.stdout))
        assert match
