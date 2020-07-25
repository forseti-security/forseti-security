# Copyright 2020 Google LLC
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

forseti_suffix = attribute('suffix')
cloudsql_password = attribute('forseti-cloudsql-password')
cloudsql_username = attribute('forseti-cloudsql-user')
cloudsql_instance_name = "forseti-server-db-#{forseti_suffix}"
forseti_server_vm_name = attribute('forseti-server-vm-name')
forseti_test_requirements = '/home/ubuntu/forseti-security/requirements-test.txt'


control "server-pytest" do
  describe command("sudo pip3 install -r #{forseti_test_requirements}") do
    its('exit_status') { should eq 0 }
  end

  describe command("sudo pytest -m server -v $FORSETI_HOME/endtoend_tests/ \
        --ignore=$FORSETI_HOME/endtoend_tests/forseti/inventory \
        --cloudsql_instance_name=#{cloudsql_instance_name} \
        --cloudsql_password=#{cloudsql_password} \
        --cloudsql_username=#{cloudsql_username} \
        --forseti_server_vm_name=#{forseti_server_vm_name}") do
    its('exit_status') { should eq 0 }
    its('stdout') { should match(/test_cv_cloudsql_location PASSED/) }
    its('stdout') { should match(/test_cv_compute_zone PASSED/) }
    its('stdout') { should match(/test_cv_scan PASSED/) }
    its('stdout') { should match(/test_model_roles PASSED/) }
  end
end
