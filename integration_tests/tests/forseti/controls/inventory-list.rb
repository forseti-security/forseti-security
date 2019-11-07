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

DB_USER_NAME = attribute('db_user_name')
DB_PASSWORD = attribute('db_password')
RANDOM_STRING = SecureRandom.uuid.gsub!('-', '')

control "inventory - list" do
  @inventory_id = /\"id\"\: \"([0-9]*)\"/.match(command("forseti inventory create --import_as #{RANDOM_STRING}").stdout)[1]

  describe command("forseti model use #{RANDOM_STRING}") do
    its('exit_status') { should eq 0 }
  end

  describe command("forseti inventory list") do
    its('exit_status') { should eq 0 }
    its('stdout') { should match (/#{@inventory_id}/)}
  end

  describe command("mysql -u #{DB_USER_NAME} -p#{DB_PASSWORD} --host 127.0.0.1 --database forseti_security --execute \"select count(DISTINCT gcp_inventory.inventory_index_id) from gcp_inventory join inventory_index on inventory_index.id = gcp_inventory.inventory_index_id where inventory_index.id = #{@inventory_id};\"") do
    its('exit_status') { should eq 0 }
    its('stdout') { should match (/1/)}
  end

  describe command("forseti inventory delete #{@inventory_id}") do
    its('exit_status') { should eq 0 }
  end

  describe command("forseti model delete #{RANDOM_STRING}") do
    its('exit_status') { should eq 0 }
  end
end
