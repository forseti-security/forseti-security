# Copyright 2019 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

require 'json'
require 'securerandom'

db_password = attribute('forseti-cloudsql-password')
db_user_name = attribute('forseti-cloudsql-user')
forseti_server_storage_bucket = attribute('forseti-server-storage-bucket')
forseti_server_vm_name = attribute('forseti-server-vm-name')
forseti_suffix = attribute('suffix')
forseti_cloudsql_instance_name = "forseti-server-db-#{forseti_suffix}"
model_name = SecureRandom.uuid.gsub!('-', '')[0..10]
policy_library_path = '/home/ubuntu/policy-library/policy-library'

control "scanner-config-validator-gcs-policy" do
  # Arrange
  @inventory_id = /\"id\"\: \"([0-9]*)\"/.match(command("forseti inventory create --import_as #{model_name}").stdout)[1]
  describe command("forseti model use #{model_name}") do
    its('exit_status') { should eq 0 }
    its('stdout') { should_not match /Error communicating to the Forseti server./ }
  end

  # Clone Policy Library repo
  describe command("sudo rm -rf #{policy_library_path}") do
    its('exit_status') { should eq 0 }
  end

  describe command("sudo git clone https://github.com/forseti-security/policy-library.git --branch master --depth 1 #{policy_library_path}") do
    its('exit_status') { should eq 0 }
  end

  # Copy the constraints from GCS
  describe command("sudo gsutil cp -r gs://#{forseti_server_storage_bucket}/policy-library/policies #{policy_library_path}") do
    its('exit_status') { should eq 0 }
  end

  # Restart Config Validator
  describe command("sudo systemctl restart config-validator") do
    its('exit_status') { should eq 0 }
  end

  # Act
  describe command("forseti scanner run") do
    its('exit_status') { should eq 0 }
    its('stdout') { should match (/Running ConfigValidatorScanner.../) }
    its('stdout') { should match (/Scan completed/) }
    its('stdout') { should match (/Scanner Index ID: (.*[0-9]*) is created/) }
  end

  # Assert violations exist for Cloud SQL Location policy
  describe command("mysql -u #{db_user_name} -p#{db_password} --host 127.0.0.1 --database forseti_security --execute \"SELECT COUNT(*) FROM violations V JOIN forseti_security.scanner_index SI ON SI.id = V.scanner_index_id WHERE SI.inventory_index_id = #{@inventory_id} AND V.resource_id = '#{forseti_cloudsql_instance_name}' AND V.violation_type = CONCAT('CV_', V.rule_name);\"") do
    its('exit_status') { should eq 0 }
    its('stdout') { should match (/1/) }
  end

  # Assert violations exist for Compute Zone policy
  describe command("mysql -u #{db_user_name} -p#{db_password} --host 127.0.0.1 --database forseti_security --execute \"SELECT COUNT(*) FROM violations V JOIN forseti_security.scanner_index SI ON SI.id = V.scanner_index_id WHERE SI.inventory_index_id = #{@inventory_id} AND V.resource_id = '#{forseti_server_vm_name}' AND V.resource_type = 'compute.googleapis.com/Instance' AND V.violation_type = 'CONFIG_VALIDATOR_VIOLATION' AND V.rule_name = 'compute_zone_denylist';\"") do
    its('exit_status') { should eq 0 }
    its('stdout') { should match (/1/) }
  end
end
