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

cai_dump_file_gcs_paths = attribute('inventory-performance-cai-dump-paths')
cloudsql_password = attribute('forseti-cloudsql-password')
cloudsql_username = attribute('forseti-cloudsql-user')
forseti_server_bucket_name = attribute('forseti-server-storage-bucket')
forseti_server_config_path = '/home/ubuntu/forseti-security/configs/forseti_conf_server.yaml'
forseti_test_requirements = '/home/ubuntu/forseti-security/requirements-test.txt'
root_resource_id = 'organizations/5456546415'


control "inventory-performance" do
  describe command("sudo pip3 install -r #{forseti_test_requirements}") do
    its('exit_status') { should eq 0 }
  end

  describe command("sudo pytest -v $FORSETI_HOME/endtoend_tests/forseti/server/inventory \
        --cai_dump_file_gcs_paths=#{cai_dump_file_gcs_paths} \
        --cloudsql_password=#{cloudsql_password} \
        --cloudsql_username=#{cloudsql_username} \
        --forseti_server_bucket_name=#{forseti_server_bucket_name} \
        --forseti_server_config_path=#{forseti_server_config_path} \
        --root_resource_id=#{root_resource_id}") do
    its('exit_status') { should eq 0 }
    its('stdout') { should match(/test_inventory_performance PASSED/) }
  end
end
