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

"""Config Validator Cloud Zone test"""

import pytest
from sqlalchemy.sql import text


class TestConfigValidatorComputeZone:
    """Config Validator Cloud Zone test

    Run a scan and assert the Cloud Zone policy produces a violation.
    """

    @pytest.mark.e2e
    @pytest.mark.scanner
    @pytest.mark.server
    def test_cv_compute_zone(self,
                             cloudsql_connection,
                             forseti_scan_readonly,
                             forseti_server_vm_name):
        """Config Validator Cloud Zone test

        Args:
            cloudsql_connection (object): SQLAlchemy  connection for Forseti
            forseti_scan_readonly (Tuple): Scanner id & scanner process result
            forseti_server_vm_name (str): Forseti server VM name
        """
        # Arrange/Act
        scanner_id, scanner_result = forseti_scan_readonly

        # Assert violation found
        violation_type = 'CV_GCPComputeZoneConstraintV1.compute-zone-denylist'
        query = text('SELECT '
                     'COUNT(*) '
                     'FROM forseti_security.violations '
                     'WHERE '
                     'scanner_index_id = :scanner_id '
                     'AND resource_id = :forseti_server_vm_name '
                     'AND resource_type = \'compute.googleapis.com/Instance\' '
                     'AND violation_type = :violation_type')
        violation_count = (
                cloudsql_connection.execute(
                    query,
                    forseti_server_vm_name=forseti_server_vm_name,
                    scanner_id=scanner_id,
                    violation_type=violation_type)
                .fetchone())
        assert 1 == violation_count[0]
