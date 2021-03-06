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

cloudsql_password = attribute('forseti-cloudsql-password')
cloudsql_username = attribute('forseti-cloudsql-user')
cscc_source_id = attribute('cscc_source_id')
forseti_cai_storage_bucket = attribute('forseti-cai-storage-bucket')
forseti_server_bucket = attribute('forseti-server-storage-bucket')
forseti_server_vm_name = attribute('forseti-server-vm-name')
forseti_suffix = attribute('suffix')
org_id = attribute('org_id')
project_id = attribute('project_id')
forseti_test_requirements = '/home/ubuntu/forseti-security/requirements-test.txt'

cloudsql_instance_name = "forseti-server-db-#{forseti_suffix}"


control "server-pytest" do
  describe command("sudo pip3 install -r #{forseti_test_requirements}") do
    its('exit_status') { should eq 0 }
  end

  describe command("sudo pytest -m server -v $FORSETI_HOME/endtoend_tests/ \
                        --ignore=$FORSETI_HOME/endtoend_tests/forseti/inventory/inventory_performance_test.py \
                        --cloudsql_instance_name=#{cloudsql_instance_name} \
                        --cloudsql_password=#{cloudsql_password} \
                        --cloudsql_username=#{cloudsql_username} \
                        --cscc_source_id=#{cscc_source_id} \
                        --forseti_cai_storage_bucket=#{forseti_cai_storage_bucket} \
                        --forseti_server_bucket_name=#{forseti_server_bucket} \
                        --forseti_server_vm_name=#{forseti_server_vm_name} \
                        --organization_id=#{org_id} \
                        --project_id=#{project_id}") do
    its('exit_status') { should eq 0 }

    # Inventory
    its('stdout') { should match(/test_inventory_cai_gcs_export PASSED/) }
    its('stdout') { should match(/test_inventory_create PASSED/) }
    its('stdout') { should match(/test_inventory_get PASSED/) }
    its('stdout') { should match(/test_inventory_list PASSED/) }

    # Model
    its('stdout') { should match(/test_model_create PASSED/) }
    its('stdout') { should match(/test_model_delete PASSED/) }
    its('stdout') { should match(/test_model_roles PASSED/) }

    # Scanners
    its('stdout') { should match(/test_cv_cloudsql_location PASSED/) }
    its('stdout') { should match(/test_cv_compute_zone PASSED/) }
    its('stdout') { should match(/test_cv_scan PASSED/) }
    # its('stdout') { should match(/test_enabled_apis_scanner PASSED/) }
    its('stdout') { should match(/test_external_project_access_scanner PASSED/) }

    # Notifiers
    its('stdout') { should match(/test_cscc_findings_match_violations PASSED/) }
    its('stdout') { should match(/test_inventory_summary_export_gcs PASSED/) }
  end
end
