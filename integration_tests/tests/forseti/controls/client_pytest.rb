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

forseti_client_service_account = attribute('forseti-client-service-account')
forseti_server_service_account = attribute('forseti-server-service-account')
forseti_test_requirements = '/home/ubuntu/forseti-security/requirements-test.txt'
org_id = attribute('org_id')
project_id = attribute('project_id')


control "client-pytest" do
  describe command("sudo pip3 install -r #{forseti_test_requirements}") do
    its('exit_status') { should eq 0 }
  end

  describe command("sudo pytest -m client -v $FORSETI_HOME/endtoend_tests/ \
                        --forseti_client_service_account=#{forseti_client_service_account} \
                        --forseti_server_service_account=#{forseti_server_service_account} \
                        --organization_id=#{org_id} \
                        --project_id=#{project_id}") do
    its('exit_status') { should eq 0 }

    # Explain
    its('stdout') { should match(/test_access_by_resource_for_organization PASSED/) }
    its('stdout') { should match(/test_access_by_resource_for_project PASSED/) }

    # Model
    its('stdout') { should match(/test_model_use PASSED/) }
  end
end