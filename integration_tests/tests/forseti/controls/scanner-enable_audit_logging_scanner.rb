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

model_name = SecureRandom.uuid.gsub!('-', '')
forseti_tests_path = "/home/ubuntu/forseti-security/integration_tests/tests/forseti"

control 'scanner-enable-audit-logging-scanner' do
  @inventory_id = /\"id\"\: \"([0-9]*)\"/.match(command("forseti inventory create --import_as #{model_name}").stdout)[1]

  describe command("forseti model use #{model_name}") do
    its('exit_status') { should eq 0 }
  end

  #  Enable audit logging Scanner
  describe command("sudo python3 #{forseti_tests_path}/scripts/update_server_config.py enable_scanner audit_logging") do
    its('exit_status') { should eq 0 }
  end
  describe command("forseti server configuration reload") do
    its('exit_status') { should eq 0 }
  end

  # act
  describe command("forseti scanner run") do
    its('exit_status') { should eq 0 }
    its('stdout') { should match (/AuditLoggingScanner/)}
    its('stdout') { should match (/Scan completed/)}
  end

  #  Disable audit logging Scanner
  describe command("sudo python3 #{forseti_tests_path}/scripts/update_server_config.py disable_scanner audit_logging") do
    its('exit_status') { should eq 0 }
  end
  describe command("forseti server configuration reload").result do
    its('exit_status') { should eq 0 }
  end

  describe command("forseti inventory delete #{@inventory_id}") do
    its('exit_status') { should eq 0 }
  end

  describe command("forseti model delete #{model_name}") do
    its('exit_status') { should eq 0 }
  end
end
