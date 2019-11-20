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

bucket_name = attribute('test-resource-bucket-scanner-bucket')
db_user_name = attribute('db_user_name')
db_password = attribute('db_password')
if db_password.strip != ""
  db_password = "-p#{db_password}"
end
project_id = attribute('project_id')
model_name = SecureRandom.uuid.gsub!('-', '')[0..10]

control 'scanner - iam policy scanner' do
  @inventory_id = /\"id\"\: \"([0-9]*)\"/.match(command("forseti inventory create --import_as #{model_name}").stdout)[1]

  describe command("forseti model use #{model_name}") do
    its('exit_status') { should eq 0 }
  end

  scanner_run = command("forseti scanner run")

  describe scanner_run do
    its('exit_status') { should eq 0 }
  end

  @scanner_id = /Scanner Index ID: ([0-9]*) is created/.match(scanner_run.stdout)[1]

  describe command("mysql -u #{db_user_name} #{db_password} --host 127.0.0.1 --database forseti_security --execute \"SELECT COUNT(*) FROM violations V WHERE V.scanner_index_id = #{@scanner_id} AND V.violation_type = 'BUCKET_VIOLATION' AND V.resource_id = '#{bucket_name}' AND V.rule_name = 'Bucket acls rule to search for exposed buckets';\"") do
    its('exit_status') { should eq 0 }
    its('stdout') { should match (/1/)}
  end

  describe command("forseti inventory delete #{@inventory_id}") do
    its('exit_status') { should eq 0 }
  end

  describe command("forseti model delete #{model_name}") do
    its('exit_status') { should eq 0 }
  end
end
