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

random_string = SecureRandom.uuid.gsub!('-', '')[0..10]

control "notifier-temp-file-deletion" do
  # Run the command that will generate the inventory
  @inventory_id = /\"id\"\: \"([0-9]*)\"/.match(command("forseti inventory create --import_as gsc-test#{random_string}").stdout)[1]

  # Run notifier
  describe command("forseti notifier run") do
    its('exit_status') { should eq 0 }
    its('stdout') { should match(/Notification completed!/)}
  end

  # Verify temp directory has no csv files
  describe command("find /tmp -maxdepth 1 -name \"*.csv\" -printf '.' | wc -m") do
    its('exit_status') { should eq 0 }
    its('stdout') { should match(/0/)}
  end

  # Delete the inventory
  describe command("forseti inventory delete #{@inventory_id}") do
    its('exit_status') { should eq 0 }
  end

  # Delete the model
  describe command("forseti model delete #{random_string}") do
    its('exit_status') { should eq 0 }
  end
end
