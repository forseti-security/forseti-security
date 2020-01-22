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
forseti_tests_path = "/home/ubuntu/forseti-security/integration_tests/tests/forseti"
model_name = SecureRandom.uuid.gsub!('-', '')[0..10]
project_id = attribute('project_id')

control 'scanner-enabled-apis-scanner', :order => :defined do
  # Arrange
  @inventory_id = /\"id\"\: \"([0-9]*)\"/.match(command("forseti inventory create --import_as #{model_name}").stdout)[1]
  describe command("forseti model use #{model_name}") do
    its('exit_status') { should eq 0 }
  end

  # Copy rules to server
  describe command("sudo gsutil cp -r gs://#{forseti_server_bucket}/rules $FORSETI_HOME/") do
    its('exit_status') { should eq 0 }
  end

  # Enable enabled_apis Scanner
  describe command("sudo python3 #{forseti_tests_path}/scripts/update_server_config.py enable_scanner enabled_apis") do
    its('exit_status') { should eq 0 }
  end

  describe command("forseti server configuration reload") do
    its('exit_status') { should eq 0 }
    its('stdout') { should match (/\"isSuccess\": true/) }
  end
  describe command("sleep 10") do
    its('exit_status') { should eq 0 }
  end

  # Act
  describe command("forseti scanner run") do
    its('exit_status') { should eq 0 }
    its('stdout') { should match (/EnabledApisScanner/) }
    its('stdout') { should match (/Scan completed/) }
    its('stdout') { should match (/Scanner Index ID: .*([0-9]*) is created/) }
  end

  # Assert Blacklist Enabled API violations found
  describe command("mysql -u #{db_user_name} -p#{db_password} --host 127.0.0.1 --database forseti_security --execute \"SELECT COUNT(*) FROM violations V JOIN forseti_security.scanner_index SI ON SI.id = V.scanner_index_id WHERE SI.inventory_index_id = #{@inventory_id} AND V.violation_type = 'ENABLED_APIS_VIOLATION' AND V.resource_id = '#{project_id}' AND V.rule_name = 'Enabled APIs blacklist';\"") do
    its('exit_status') { should eq 0 }
    its('stdout') { should match (/1/) }
  end

  # Disable Scanner
  describe command("sudo python3 #{forseti_tests_path}/scripts/update_server_config.py disable_scanner enabled_apis") do
    its('exit_status') { should eq 0 }
  end
  describe command("forseti server configuration reload") do
    its('exit_status') { should eq 0 }
    its('stdout') { should match (/\"isSuccess\": true/) }
  end
end
