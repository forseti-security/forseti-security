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
from sqlalchemy.sql import text


class TestConfigValidatorCloudSqlLocation:
    """Config Validator Cloud SQL Location test

    Run a scan and assert the Cloud SQL Location policy
    produces a violation.
    """

    @pytest.mark.e2e
    @pytest.mark.scanner
    def test_cv_cloudsql_location(self,
                                  cloudsql_connection,
                                  cloudsql_instance_name,
                                  forseti_scan_readonly):
        """Config Validator Cloud SQL Location test

        Args:
            cloudsql_connection (object): SQLAlchemy engine connection for Forseti
            cloudsql_instance_name (str): Cloud SQL instance name
            forseti_scan_readonly (Tuple): Scanner id and scanner process result
        """
        # Arrange/Act
        scanner_id, scanner_result = forseti_scan_readonly

        # Assert violation found
        violation_type = 'CV_sql_location_denylist'
        query = text('SELECT '
                     'COUNT(*) '
                     'FROM forseti_security.violations '
                     'WHERE '
                     'scanner_index_id = :scanner_id '
                     'AND resource_id = :cloudsql_instance_name '
                     'AND violation_type = :violation_type')
        violation_count = (
                cloudsql_connection.execute(
                    query,
                    cloudsql_instance_name=cloudsql_instance_name,
                    scanner_id=scanner_id,
                    violation_type=violation_type)
                .fetchone())
        assert 1 == violation_count[0]
