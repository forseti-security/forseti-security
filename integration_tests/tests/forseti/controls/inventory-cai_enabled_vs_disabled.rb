# Copyright 2019 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
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
forseti_server_bucket = attribute('forseti-server-storage-bucket')
model_name = SecureRandom.uuid.gsub!('-', '')[0..10]
model_name_enabled = "CaiEnabled#{model_name}"
model_name_disabled = "CaiDisabled#{model_name}"

control 'inventory-cai-enabled-vs-disabled' do
  # Copy rules to server
  describe command("sudo gsutil cp -r gs://#{forseti_server_bucket}/rules $FORSETI_HOME/") do
    its('exit_status') { should eq 0 }
  end

  # Create inventory with CAI enabled
  @inventory_id_enabled = /\"id\"\: \"([0-9]*)\"/.match(command("forseti inventory create --import_as #{model_name_enabled}").stdout)[1]
  describe command("forseti model use #{model_name_enabled}") do
    its('exit_status') { should eq 0 }
    its('stdout') { should_not match(/Error communicating to the Forseti server/) }
  end

  # Run scan for CAI enabled
  describe command("forseti scanner run") do
    its('exit_status') { should eq 0 }
    its('stdout') { should match(/Scan completed/) }
    its('stdout') { should match(/Scanner Index ID: ([0-9]*) is created/) }
  end

  # Disable CAI
  describe command("sudo python3 /home/ubuntu/forseti-security/integration_tests/tests/forseti/scripts/update_server_config.py set_cai_enabled false") do
    its('exit_status') { should eq 0 }
  end

  # Create inventory with CAI disabled
  @inventory_id_disabled = /\"id\"\: \"([0-9]*)\"/.match(command("forseti inventory create --import_as #{model_name_disabled}").stdout)[1]
  describe command("forseti model use #{model_name_disabled}") do
    its('exit_status') { should eq 0 }
    its('stdout') { should_not match /Error communicating to the Forseti server/ }
  end

  # Run scan for CAI disabled
  describe command("forseti scanner run") do
    its('exit_status') { should eq 0 }
    its('stdout') { should match(/Scan completed/) }
    its('stdout') { should match(/Scanner Index ID: ([0-9]*) is created/) }
  end

  # Assert violation count
  # This query unions the two violation sets together and looks for violations that only have a count of 1.
  # If the violation results match, then they will have a count of 2 (one for each scan).
  describe command("mysql -u #{db_user_name} -p#{db_password} --host 127.0.0.1 --database forseti_security --execute \"SELECT COUNT(resource_id) FROM (SELECT V.violation_type, V.resource_id, V.resource_type, V.rule_name FROM violations V JOIN scanner_index SI ON SI.id = V.scanner_index_id WHERE SI.inventory_index_id = #{@inventory_id_enabled} UNION ALL SELECT V.violation_type, V.resource_id, V.resource_type, V.rule_name FROM violations V JOIN scanner_index SI ON SI.id = V.scanner_index_id WHERE SI.inventory_index_id = #{@inventory_id_disabled}) Violations WHERE violation_type in ('BUCKET_VIOLATION', 'FIREWALL_BLACKLIST_VIOLATION', 'IAM_POLICY_VIOLATION', 'LOCATION_VIOLATION') GROUP BY violation_type, resource_id, resource_type, rule_name HAVING COUNT(*) = 1;\"") do
    its('exit_status') { should eq 0 }
    its('stdout') { should match(//) }
  end

  # Re-enable CAI
  describe command("sudo python3 /home/ubuntu/forseti-security/integration_tests/tests/forseti/scripts/update_server_config.py set_cai_enabled true") do
    its('exit_status') { should eq 0 }
  end

  # Cleanup
  describe command("forseti inventory delete #{@inventory_id_enabled}") do
    its('exit_status') { should eq 0 }
  end

  describe command("forseti model delete #{model_name_enabled}") do
    its('exit_status') { should eq 0 }
  end

  describe command("forseti inventory delete #{@inventory_id_disabled}") do
    its('exit_status') { should eq 0 }
  end

  describe command("forseti model delete #{model_name_disabled}") do
    its('exit_status') { should eq 0 }
  end
end
