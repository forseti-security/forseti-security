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

db_user_name = attribute('db_user_name')
db_password = attribute('db_password')
if db_password.strip != ""
  db_password = "-p#{db_password}"
end
random_string = SecureRandom.uuid.gsub!('-', '')[0..10]

control "model - create and get" do
  @inventory_id = /\"id\"\: \"([0-9]*)\"/.match(command("forseti inventory create --import_as #{random_string}").stdout)[1]

  describe command("forseti model use #{random_string}") do
    its('exit_status') { should eq 0 }
  end

  describe command("forseti model get #{random_string}") do
    its('exit_status') { should eq 0 }
    its('stdout') { should match (/#{random_string}/)}
    its('stdout') { should match (/PARTIAL_SUCCESS/)}
  end

  describe command("mysql -u #{db_user_name} #{db_password} --host 127.0.0.1 --database forseti_security --execute \"select state from model where name = '#{random_string}';\"") do
    its('exit_status') { should eq 0 }
    its('stdout') { should match (/PARTIAL_SUCCESS/)}
  end

  describe command("forseti inventory delete #{@inventory_id}") do
    its('exit_status') { should eq 0 }
  end

  describe command("forseti model delete #{random_string}") do
    its('exit_status') { should eq 0 }
  end
end
