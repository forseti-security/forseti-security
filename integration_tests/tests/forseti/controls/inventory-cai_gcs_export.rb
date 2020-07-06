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

forseti_cai_storage_bucket = attribute('forseti-cai-storage-bucket')
org_id = attribute('org_id')
model_name = SecureRandom.uuid.gsub!('-', '')[0..10]

control "inventory-cai-gcs-export" do
  # Act
  inventory_create = command("forseti inventory create --import_as #{model_name}")
  describe inventory_create do
    its('exit_status') { should eq 0 }
    its('stdout') { should match /"id": "([0-9]*)"/}
  end
  @inventory_id = /"id": "([0-9]*)"/.match(inventory_create.stdout)[1]
  gs_file = "gs://#{forseti_cai_storage_bucket}/organizations-#{org_id}-resource-#{@inventory_id}.dump"

  # Assert
  describe command("sudo gsutil ls #{gs_file}") do
    its('exit_status') { should eq 0 }
  end

  # Cleanup
  describe command("forseti model delete #{model_name}") do
    its('exit_status') { should eq 0 }
  end

  describe command("forseti inventory delete #{@inventory_id}") do
    its('exit_status') { should eq 0 }
  end
end
