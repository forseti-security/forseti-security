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

kms_resources_names = attribute('kms_resources_names')

require 'json'
control "scanner - external project access" do
  before :context do
    command("forseti inventory purge 0").result
    command("forseti inventory create").result
    inventory_id = JSON.parse(command("forseti inventory list").stdout).fetch("id")
    command("forseti model create --inventory_index_id #{inventory_id} model_new").result
    command("forseti model use model_new").result
  end

  describe command("forseti scanner run --scanner external_project_access_scanner") do
    its('exit_status') { should eq 0 }
    its('output') { should match (/Scanner Index ID: [0-9]* is created/)}
    its('output') { should match (/Running ExternalProjectAccessScanner.../)}
    its('output') { should match (/Scan completed!/)}
  end

  after(:context) do
    command("forseti inventory purge 0").result
    command("forseti model delete model_new").result
  end
end
