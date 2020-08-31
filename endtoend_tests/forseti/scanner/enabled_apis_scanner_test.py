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

"""Enabled APIs Scanner test"""

import pytest
import re
from sqlalchemy.sql import text


class TestEnabledApisScannerTest:
    """Enabled APIs Scanner test

    Run a scan, assert Enabled API scanner is run, and finds the violation.
    Violation rule is installed as part of e2e test fixture in Terraform.
    """

    @pytest.mark.e2e
    @pytest.mark.scanner
    @pytest.mark.server
    def test_enabled_apis_scanner(self, cloudsql_connection,
                                  forseti_scan_readonly,
                                  project_id):
        """Enabled APIs Scanner test

        Args:
            cloudsql_connection (object): SQLAlchemy  connection for Forseti
            forseti_scan_readonly (Tuple): Scanner id & scanner process result
            project_id (str): Project id being scanned
        """
        # Arrange/Act
        scanner_id, scanner_result = forseti_scan_readonly
        violation_type = 'ENABLED_APIS_VIOLATION'
        violation_rule_name = 'Restrict Compute Engine API'

        # Assert scanner id
        assert scanner_id

        # Assert Enabled APIs Scanner was run
        regex = re.compile('EnabledApisScanner')
        match = regex.search(str(scanner_result.stdout))
        assert match

        # Assert scan completed
        regex = re.compile('Scan completed')
        match = regex.search(str(scanner_result.stdout))
        assert match

        # Asset violation is found
        query = text('SELECT '
                     'COUNT(*) '
                     'FROM forseti_security.violations V '
                     'WHERE '
                     'V.scanner_index_id = :scanner_id '
                     'AND V.resource_id = :project_id '
                     'AND V.rule_name = :violation_rule_name '
                     'AND V.violation_type = :violation_type')
        violation_count = (
                cloudsql_connection.execute(
                    query,
                    project_id=project_id,
                    scanner_id=scanner_id,
                    violation_rule_name=violation_rule_name,
                    violation_type=violation_type)
                .fetchone())
        assert 1 == violation_count[0]
