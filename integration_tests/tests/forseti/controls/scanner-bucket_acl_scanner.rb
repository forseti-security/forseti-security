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

bucket_name = attribute('bucket_acl_scanner_bucket_name')
db_user_name = attribute('forseti-cloudsql-user')
db_password = attribute('forseti-cloudsql-password')
model_name = SecureRandom.uuid.gsub!('-', '')[0..10]

control 'scanner-bucket-acl-scanner', :order => :defined do
  # Arrange
  describe command("forseti inventory create --import_as #{model_name}") do
    its('exit_status') { should eq 0 }
  end

  describe command("forseti model use #{model_name}") do
    its('exit_status') { should eq 0 }
  end

  # Act
  scanner_run_cmd = command("forseti scanner run")
  describe scanner_run_cmd do
    its('exit_status') { should eq 0 }
    its('stdout') { should match /Scanner Index ID: (.*[0-9].*) is created/ }
  end
  @scanner_id = /Scanner Index ID: (.*[0-9]*) is created/.match(scanner_run_cmd.stdout)[1]

  # Assert AllAuth violation found
  describe command("mysql -u #{db_user_name} -p#{db_password} --host 127.0.0.1 --database forseti_security --execute \"SELECT COUNT(*) FROM violations V WHERE V.scanner_index_id = #{@scanner_id} AND V.violation_type = 'BUCKET_VIOLATION' AND V.resource_id = '#{bucket_name}' AND V.rule_name = 'Bucket acls rule to search for exposed buckets';\"") do
    its('exit_status') { should eq 0 }
    its('stdout') { should match (/1/)}
  end

  # Assert AllUsers violation found
  describe command("mysql -u #{db_user_name} -p#{db_password} --host 127.0.0.1 --database forseti_security --execute \"SELECT COUNT(*) FROM violations V WHERE V.scanner_index_id = #{@scanner_id} AND V.violation_type = 'BUCKET_VIOLATION' AND V.resource_id = '#{bucket_name}' AND V.rule_name = 'Bucket acls rule to search for public buckets';\"") do
    its('exit_status') { should eq 0 }
    its('stdout') { should match (/1/)}
  end
end
