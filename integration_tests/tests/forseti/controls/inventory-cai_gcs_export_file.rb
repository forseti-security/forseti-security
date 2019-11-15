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

suffix = attribute('suffix')
org_id = attribute('org_id')

random_string = SecureRandom.uuid.gsub!('-', '')[0..10]

control "inventory - cai gcs export file" do
  @inventory_id = /\"id\"\: \"([0-9]*)\"/.match(command("forseti inventory create --import_as #{random_string}").stdout)[1]
  gs_file = "gs://#{forseti-cai-storage-bucket}/organizations-#{org_id}-resource-#{@inventory_id}.dump"

  describe command("gsutil ls #{gs_file} | grep #{gs_file}") do
    its('stdout') { should match (gs_file)}
  end

  describe command("forseti model delete #{random_string}") do
    its('exit_status') { should eq 0 }
  end

  describe command("forseti inventory delete #{@inventory_id}") do
    its('exit_status') { should eq 0 }
  end
end
