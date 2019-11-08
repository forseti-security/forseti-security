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

random_string = SecureRandom.uuid.gsub!('-', '')

control 'scanner - enable audit logging scanner' do
  @inventory_id = /\"id\"\: \"([0-9]*)\"/.match(command("forseti inventory create --import_as #{random_string}").stdout)[1]

  describe command("forseti model use #{random_string}") do
    its('exit_status') { should eq 0 }
  end

  # update server config to enable audit logging scanner
  command("sudo cp /home/ubuntu/forseti-security/configs/forseti_conf_server.yaml /home/ubuntu/forseti-security/configs/forseti_conf_server_backup.yaml").result
  @modified_yaml = yaml('/home/ubuntu/forseti-security/configs/forseti_conf_server.yaml').params
  @scanner_index = @modified_yaml["scanner"]["scanners"].find_index { |scanner| scanner["name"] == "audit_logging" }
  @modified_yaml["scanner"]["scanners"][@scanner_index]["enabled"] = "true"
  command("echo -en \"#{@modified_yaml.to_yaml}\" | sudo tee /home/ubuntu/forseti-security/configs/forseti_conf_server.yaml").result
  command("forseti server configuration reload").result

  # act
  describe command("forseti scanner run") do
    its('exit_status') { should eq 0 }
    its('stdout') { should match (/AuditLoggingScanner/)}
    its('stdout') { should match (/Scan completed/)}
  end

  # disable audit logging scanner
  describe command("sudo mv /home/ubuntu/forseti-security/configs/forseti_conf_server_backup.yaml /home/ubuntu/forseti-security/configs/forseti_conf_server.yaml") do
    its('exit_status') { should eq 0 }
  end
  describe command("forseti server configuration reload").result do
    its('exit_status') { should eq 0 }
  end

  describe command("forseti inventory delete #{@inventory_id}") do
    its('exit_status') { should eq 0 }
  end

  describe command("forseti model delete #{random_string}") do
    its('exit_status') { should eq 0 }
  end
end
