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

all_auth_bucket_name = attribute('bucket_acl_scanner_all_auth_bucket_name')
all_users_bucket_name = attribute('bucket_acl_scanner_all_users_bucket_name')
db_password = attribute('forseti-cloudsql-password')
db_user_name = attribute('forseti-cloudsql-user')
model_name = SecureRandom.uuid.gsub!('-', '')[0..10]

control 'scanner-bucket-acl-scanner', :order => :defined do
  # Arrange
  @inventory_id = /\"id\"\: \"([0-9]*)\"/.match(command("forseti inventory create --import_as #{model_name}").stdout)[1]
  describe command("forseti model use #{model_name}") do
    its('exit_status') { should eq 0 }
  end

  # Act
  describe command("forseti scanner run") do
    its('exit_status') { should eq 0 }
    its('stdout') { should match /Scanner Index ID: (.*[0-9].*) is created/ }
  end

  # Assert AllAuth violation found
  describe command("mysql -u #{db_user_name} -p#{db_password} --host 127.0.0.1 --database forseti_security --execute \"SELECT COUNT(*) FROM violations V JOIN forseti_security.scanner_index SI ON SI.id = V.scanner_index_id WHERE SI.inventory_index_id = #{@inventory_id} AND V.violation_type = 'BUCKET_VIOLATION' AND V.resource_id = '#{all_auth_bucket_name}' AND V.rule_name = 'Bucket acls rule to search for exposed buckets';\"") do
    its('exit_status') { should eq 0 }
    its('stdout') { should match (/1/) }
  end

  # Assert AllUsers violation found
  describe command("mysql -u #{db_user_name} -p#{db_password} --host 127.0.0.1 --database forseti_security --execute \"SELECT COUNT(*) FROM violations V JOIN forseti_security.scanner_index SI ON SI.id = V.scanner_index_id WHERE SI.inventory_index_id = #{@inventory_id} AND V.violation_type = 'BUCKET_VIOLATION' AND V.resource_id = '#{all_users_bucket_name}' AND V.rule_name = 'Bucket acls rule to search for public buckets';\"") do
    its('exit_status') { should eq 0 }
    its('stdout') { should match (/1/) }
  end
end
