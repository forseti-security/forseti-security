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

db_user_name = attribute('forseti-cloudsql-user')
db_password = attribute('forseti-cloudsql-password')
# scanner_test_big_query_id =  attribute('scanner-test-big-query-id')

control "scanner-big-query" do
  # Act
  scanner_run = command("forseti scanner run")
  @scanner_id = /Scanner Index ID: ([0-9]*) is created/.match(scanner_run.stdout)[1]
  describe scanner_run do
    its('exit_status') { should eq 0 }
  end

  # Assert AllAuth violation found
  describe command("mysql -u #{db_user_name} -p#{db_password} --host 127.0.0.1 --database forseti_security --execute \"SELECT COUNT(*) FROM violations V WHERE V.scanner_index_id = #{@scanner_id} AND V.violation_type = 'BIGQUERY_VIOLATION' AND V.rule_name = 'Bucket acls rule to search for exposed buckets';\"") do
  # describe command("mysql -u #{db_user_name} -p#{db_password} --host 127.0.0.1 --database forseti_security --execute \"SELECT COUNT(*) FROM violations V WHERE V.scanner_index_id = #{@scanner_id} AND V.violation_type = 'BIGQUERY_VIOLATION' AND V.resource_id = '#{scanner_test_big_query_id}' AND V.rule_name = 'Bucket acls rule to search for exposed buckets';\"") do
    its('exit_status') { should eq 0 }
    its('stdout') { should match (/1/)}
  end
end