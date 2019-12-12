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

db_user_name = attribute('forseti-cloudsql-user')
db_password = attribute('forseti-cloudsql-password')
forseti_server_bucket = attribute('forseti-server-storage-bucket')
model_name = SecureRandom.uuid.gsub!('-', '')[0..10]
project_id = attribute('project_id')

control 'scanner-enabled-apis-scanner' do
  # Arrange
  describe command("forseti inventory create --import_as #{model_name}") do
    its('exit_status') { should eq 0 }
  end

  describe command("forseti model use #{model_name}") do
    its('exit_status') { should eq 0 }
  end

  # Enable Scanner
  @modified_yaml = yaml('/home/ubuntu/forseti-security/configs/forseti_conf_server.yaml').params
  @scanner_index = @modified_yaml["scanner"]["scanners"].find_index { |scanner| scanner["name"] == "enabled_apis" }
  @modified_yaml["scanner"]["scanners"][@scanner_index]["enabled"] = true
  describe command("echo -en \"#{@modified_yaml.to_yaml}\" | sudo tee /home/ubuntu/forseti-security/configs/forseti_conf_server.yaml") do
    its('exit_status') { should eq 0 }
  end
  describe command("forseti server configuration reload") do
    its('exit_status') { should eq 0 }
  end
  describe command("sudo gsutil cp -r gs://#{forseti_server_bucket}/rules $FORSETI_HOME/") do
    its('exit_status') { should eq 0 }
  end

  # Act
  scanner_run = command("forseti scanner run")
  @scanner_id = /Scanner Index ID: ([0-9]*) is created/.match(scanner_run.stdout)[1]
  describe scanner_run do
    its('exit_status') { should eq 0 }
    its('stdout') { should match (/EnabledApisScanner/) }
    its('stdout') { should match (/Scan completed/) }
  end

  # Disable Scanner
  @modified_yaml["scanner"]["scanners"][@scanner_index]["enabled"] = false
  describe command("echo -en \"#{@modified_yaml.to_yaml}\" | sudo tee /home/ubuntu/forseti-security/configs/forseti_conf_server.yaml") do
    its('exit_status') { should eq 0 }
  end
  describe command("forseti server configuration reload").result do
    its('exit_status') { should eq 0 }
  end

  # Assert Blacklist Enabled API violations found
  describe command("mysql -u #{db_user_name} -p#{db_password} --host 127.0.0.1 --database forseti_security --execute \"SELECT COUNT(*) FROM violations V WHERE V.scanner_index_id = #{@scanner_id} AND V.violation_type = 'ENABLED_APIS_VIOLATION' AND V.resource_id = '#{project_id}' AND V.rule_name = 'Enabled APIs blacklist';\"") do
    its('exit_status') { should eq 0 }
    its('stdout') { should match (/1/)}
  end
end
