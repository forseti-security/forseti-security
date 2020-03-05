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

import json
import os
import pytest
import subprocess
from sqlalchemy.sql import text

POLICY_LIBRARY_COMMIT = '8e1a6ca'
POLICY_LIBRARY_PATH = '/home/ubuntu/policy-library/policy-library'
POLICY_LIBRARY_REPO_URL = 'https://github.com/forseti-security/policy-library.git'


class TestConfigValidatorCloudSqlLocation:
    """Inventory Performance test

    Create an inventory and model using mocked CAI resources and assert
    the inventory is completed in 15 minutes or less, and that the mock
    resources are created in the inventory.
    """

    @staticmethod
    def setup_policy_library(forseti_server_bucket_name):
        """
        :return:
        """
        clear_cmd = ['sudo', 'rm', '-rf', POLICY_LIBRARY_PATH]
        subprocess.run(clear_cmd)

        # Clone Policy Library and checkout working commit
        clone_cmd = ['sudo', 'git', 'clone', POLICY_LIBRARY_REPO_URL, POLICY_LIBRARY_PATH]
        subprocess.run(clone_cmd)
        git_path = os.path.join(POLICY_LIBRARY_PATH, '.git')
        git_reset_cmd = ['sudo', 'git', '--git-dir', git_path, 'reset', '--hard']
        subprocess.run(git_reset_cmd)
        checkout_cmd = ['sudo', 'git', '--git-dir', git_path, 'checkout', POLICY_LIBRARY_COMMIT]
        subprocess.run(checkout_cmd)

        # Copy test constraints from GCS
        gcs_path = f'gs://{forseti_server_bucket_name}/policy-library/policies'
        copy_cmd = ['sudo', 'gsutil', 'cp', '-r', gcs_path, POLICY_LIBRARY_PATH]
        subprocess.run(copy_cmd)

        # Reset CV
        reset_cmd = ['sudo', 'systemctl', 'restart', 'config-validator']
        subprocess.run(reset_cmd)

    @pytest.mark.e2e
    @pytest.mark.scanner
    def test_cv_cloudsql_location(self,
                                  cloudsql_connection,
                                  cloudsql_instance_name,
                                  forseti_cli,
                                  forseti_model_name_readonly,
                                  forseti_server_bucket_name):
        """Config Validator Cloud SQL Location test

        Args:
            cloudsql_connection (object): SQLAlchemy engine connection for Forseti
            cloudsql_instance_name (str): Cloud SQL instance name
            forseti_cli (object): Forseti CLI helper class instance
            forseti_model_name_readonly (str): Forseti model name
            forseti_server_bucket_name (str): Forseti server bucket name
        """
        # Arrange
        TestConfigValidatorCloudSqlLocation.setup_policy_library(
            forseti_server_bucket_name)

        # Act
        forseti_cli.model_use(forseti_model_name_readonly)
        scanner_id, _ = forseti_cli.scanner_run()
        """
        describe command("forseti model use #{model_name} && forseti scanner run && forseti notifier run --inventory_index_id #{@inventory_id}") do
    its('exit_status') { should eq 0 }
    its('stdout') { should_not match(/Error communicating to the Forseti server./) }
    its('stdout') { should match(/Running ConfigValidatorScanner.../) }
    its('stdout') { should match(/Scan completed/) }
    its('stdout') { should match(/Scanner Index ID: (.*[0-9]*) is created/) }
    its('stdout') { should match(/Notification completed!/) }
    its('stdout') { should match(/Retrieved ([0-9]*) violations for resource 'config_validator_violations'/) }
  end
  """

        # Assert violation found
        violation_type = 'CV_sql_location_denylist'
        query = text('SELECT '
                     'COUNT(*) '
                     'FROM forseti_security.violations'
                     'WHERE '
                     'scanner_index_id = :scanner_id'
                     'AND resource_id = :cloudsql_instance_name'
                     'AND violation_type = :violation_type')
        violation_count = (
                cloudsql_connection.execute(query,
                                            cloudsql_instance_name=cloudsql_instance_name,
                                            scanner_id=scanner_id,
                                            violation_type=violation_type)
                .fetchone())
        assert 1 == violation_count[0]
