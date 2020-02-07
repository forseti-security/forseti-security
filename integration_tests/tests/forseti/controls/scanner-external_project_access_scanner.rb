# Copyright 2018 Google LLC
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

require 'securerandom'
require 'json'

random_string = SecureRandom.uuid.gsub!('-', '')[0..10]

control "scanner-external-project-access-scanner" do
  @inventory_id = /\"id\"\: \"([0-9]*)\"/.match(command("forseti inventory create --import_as #{random_string}").stdout)[1]
  
  describe command("forseti model use #{random_string}") do
    its('exit_status') { should eq 0 }
  end

  describe command("forseti scanner run --scanner external_project_access_scanner") do
    its('exit_status') { should eq 0 }
    its('stdout') { should match (/Scanner Index ID: .*[0-9]* is created/)}
    its('stdout') { should match (/Running ExternalProjectAccessScanner.../)}
    its('stdout') { should match (/Scan completed!/)}
  end

  describe command("forseti inventory delete #{@inventory_id}") do
    its('exit_status') { should eq 0 }
  end

  describe command("forseti model delete " + random_string) do
    its('exit_status') { should eq 0 }
  end
end
