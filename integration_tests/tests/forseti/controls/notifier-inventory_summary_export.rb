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

require 'securerandom'
require 'json'

model_name = SecureRandom.uuid.gsub!('-', '')[0..10]
suffix = attribute('suffix')

control "notifier-inventory-summary-export" do
  # Arrange
  inventory_create = command("forseti inventory create --import_as #{model_name}")
  describe inventory_create do
    its('exit_status') { should eq 0 }
    its('stdout') { should match(/"id": "([0-9]*)"/) }
  end
  @inventory_id = /"id": "([0-9]*)"/.match(inventory_create.stdout)[1]

  scanner_run = command("forseti model use #{model_name} && forseti scanner run")
  describe scanner_run do
    its('exit_status') { should eq 0 }
    its('stdout') { should match(/Scanner Index ID: .*([0-9]*) is created/) }
  end
  @scanner_id = /Scanner Index ID: .*([0-9]*) is created/.match(scanner_run.stdout)[1]

  # Act
  notifier_run = command("forseti notifier run")
  describe notifier_run do
    its('exit_status') { should eq 0 }
    its('stdout') { should match(/Notification completed!/) }
    its('stdout') { should match(/file saved to GCS path: (gs:\/\/[a-z\-0-9\/_.TZ]*)"\n}/) }
  end
  
  # Assert
  gs_csv_file_path = /file saved to GCS path: (gs:\/\/[a-z\-0-9\/_.TZ]*)"\n}/.match(notifier_run.stdout)[1]
  describe command("sudo gsutil ls #{gs_csv_file_path}") do
    its('exit_status') { should eq 0 }
  end

  # Delete the inventory
  describe command("forseti inventory delete #{@inventory_id}") do
    its('exit_status') { should eq 0 }
  end

  # Delete the model
  describe command("forseti model delete #{model_name}") do
    its('exit_status') { should eq 0 }
  end
end
