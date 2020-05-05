# Copyright 2020 The Forseti Security Authors. All rights reserved.
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

require 'json'

db_user_name = attribute('forseti-cloudsql-user')
db_password = attribute('forseti-cloudsql-password')
model_name = SecureRandom.uuid.gsub!('-', '')[0..10]

control "scanner-run" do
  create_cmd = command("forseti inventory create --import_as #{model_name}")
  describe create_cmd do
    its('exit_status') { should eq 0 }
    its('stdout') { should match /\"id\"\: \"([0-9]*)\"/ }
    its('stdout') { should_not match /Error communicating to the Forseti server./ }
  end
  @inventory_id = /\"id\"\: \"([0-9]*)\"/.match(create_cmd.stdout)[1]

  scanner_run_cmd = command("forseti model use #{model_name} && forseti scanner run")
  describe scanner_run_cmd do
    its('exit_status') { should eq 0 }
    its('stdout') { should match /Scanner Index ID: (.*[0-9].*) is created/ }
  end
  @scanner_index_id = /Scanner Index ID: (.*[0-9]*) is created/.match(scanner_run_cmd.stdout)[1]

  describe command("mysql -u #{db_user_name} -p#{db_password} --host 127.0.0.1 --database forseti_security --execute \"SELECT SI.* FROM scanner_index SI WHERE id = #{@scanner_index_id};\"") do
    its('exit_status') { should eq 0 }
    its('stdout') { should match (/SUCCESS/) }
  end

  describe command("forseti inventory delete #{@inventory_id}") do
    its('exit_status') { should eq 0 }
  end

  describe command("forseti model delete #{model_name}") do
    its('exit_status') { should eq 0 }
  end
end
