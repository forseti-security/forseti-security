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

forseti_client_service_account = attribute('forseti-client-service-account')
forseti_server_service_account = attribute('forseti-server-service-account')
org_id = attribute('org_id')
project_id = attribute('project_id')
random_string = SecureRandom.uuid.gsub!('-', '')[0..10]

control "explain" do
  @inventory_id = /\"id\"\: \"([0-9]*)\"/.match(command("forseti inventory create --import_as #{random_string}").stdout)[1]
  describe command("forseti model use #{random_string}") do
    its('exit_status') { should eq 0 }
  end

  # access_by_member
  describe command("forseti explainer access_by_member serviceaccount/#{forseti_server_service_account}") do
    its('exit_status') { should eq 0 }
    its('stdout') { should match (/"resources": \[\n    "organization\/#{Regexp.quote(org_id)}"\n  \],\n  "role": "roles\/browser"/) }
    its('stdout') { should match (/"resources": \[\n    "organization\/#{Regexp.quote(org_id)}"\n  \],\n  "role": "roles\/iam.securityReviewer"/) }
    its('stdout') { should match (/"resources": \[\n    "project\/#{Regexp.quote(project_id)}"\n  \],\n  "role": "roles\/cloudsql.client"/) }
  end

  # access_by_member storage.buckets.lists
  describe command("forseti explainer access_by_member serviceaccount/#{forseti_server_service_account} storage.buckets.list") do
    its('exit_status') { should eq 0 }
    its('stdout') { should match (/"resources": \[\n    "organization\/#{Regexp.quote(org_id)}"\n  \],\n  "role": "roles\/iam.securityReviewer"/) }
  end

  # access_by_authz by permission
  describe command("forseti explainer access_by_authz --permission iam.serviceAccounts.get") do
    its('exit_status') { should eq 0 }
    its('stdout') { should match (/"resource": "project\/#{project_id}"/) }
    its('stdout') { should match (/"role": "roles\/editor"/) }
  end

  # access_by_authz by role
  describe command("forseti explainer access_by_authz --role roles/storage.objectCreator") do
    its('exit_status') { should eq 0 }
    its('stdout') { should match (/#{project_id}/) }
    its('stdout') { should match (/serviceaccount\/#{forseti_server_service_account}/) }
  end

  # access_by_resource organization
  describe command("forseti explainer access_by_resource organization/#{org_id} | grep -c #{forseti_server_service_account}") do
    its('exit_status') { should eq 0 }
    its('stdout') { should match (/10/) }
  end

  # access_by_resource project
  describe command("forseti explainer access_by_resource project/#{project_id} | grep -c #{forseti_server_service_account}") do
    its('exit_status') { should eq 0 }
    its('stdout') { should match (/16/) }
  end

  # get_policy for org
  describe command("forseti explainer get_policy organization/#{org_id} | grep -c #{forseti_server_service_account}") do
    its('exit_status') { should eq 0 }
    its('stdout') { should match (/10/) }
  end

  # get_policy for project
  describe command("forseti explainer get_policy project/#{project_id} | grep -c #{forseti_server_service_account}") do
    its('exit_status') { should eq 0 }
    its('stdout') { should match (/6/) }
  end

  # list_members
  describe command("forseti explainer list_members") do
    its('exit_status') { should eq 0 }
    its('stdout') { should match (/serviceaccount\/#{Regexp.quote(forseti_client_service_account)}/) }
    its('stdout') { should match (/serviceaccount\/#{Regexp.quote(forseti_server_service_account)}/) }
    its('stdout') { should match (/projectowner\/#{Regexp.quote(project_id)}/) }
  end

  # list_members --prefix forseti
  describe command("forseti explainer list_members --prefix forseti") do
    its('exit_status') { should eq 0 }
    its('stdout') { should match (/serviceaccount\/#{Regexp.quote(forseti_client_service_account)}/) }
    its('stdout') { should match (/serviceaccount\/#{Regexp.quote(forseti_server_service_account)}/) }
  end

  # list_permissions roles/iam.roleAdmin
  describe command("forseti explainer list_permissions --roles roles/iam.roleAdmin") do
    its('exit_status') { should eq 0 }
    its('stdout') { should match (/iam.roles.create/) }
    its('stdout') { should match (/iam.roles.delete/) }
    its('stdout') { should match (/iam.roles.get/) }
    its('stdout') { should match (/iam.roles.list/) }
    its('stdout') { should match (/iam.roles.undelete/) }
    its('stdout') { should match (/iam.roles.update/) }
    its('stdout') { should match (/resourcemanager.projects.get/) }
    its('stdout') { should match (/resourcemanager.projects.getIamPolicy/) }
  end

  # list_permissions roles/storage.admin
  describe command("forseti explainer list_permissions --roles roles/storage.admin") do
    its('exit_status') { should eq 0 }
    its('stdout') { should match (/storage.buckets.create/) }
    its('stdout') { should match (/storage.buckets.delete/) }
    its('stdout') { should match (/storage.buckets.get/) }
    its('stdout') { should match (/storage.buckets.getIamPolicy/) }
    its('stdout') { should match (/storage.buckets.list/) }
    its('stdout') { should match (/storage.buckets.setIamPolicy/) }
    its('stdout') { should match (/storage.buckets.update/) }
    its('stdout') { should match (/storage.objects.create/) }
    its('stdout') { should match (/storage.objects.delete/) }
    its('stdout') { should match (/storage.objects.get/) }
    its('stdout') { should match (/storage.objects.getIamPolicy/) }
    its('stdout') { should match (/storage.objects.list/) }
    its('stdout') { should match (/storage.objects.setIamPolicy/) }
    its('stdout') { should match (/storage.objects.update/) }
  end

  # list_permissions prefixes roles/storage
  describe command("forseti explainer list_permissions --role_prefixes roles/storage") do
    its('exit_status') { should eq 0 }
    its('stdout') { should match (/roles\/storage.admin/) }
    its('stdout') { should match (/roles\/storage.hmacKeyAdmin/) }
    its('stdout') { should match (/roles\/storage.legacyBucketOwner/) }
    its('stdout') { should match (/roles\/storage.legacyBucketReader/) }
    its('stdout') { should match (/roles\/storage.legacyBucketWriter/) }
    its('stdout') { should match (/roles\/storage.legacyObjectOwner/) }
    its('stdout') { should match (/roles\/storage.legacyObjectReader/) }
    its('stdout') { should match (/roles\/storage.objectAdmin/) }
    its('stdout') { should match (/roles\/storage.objectCreator/) }
    its('stdout') { should match (/roles\/storage.objectViewer/) }
    its('stdout') { should match (/roles\/storagetransfer.admin/) }
    its('stdout') { should match (/roles\/storagetransfer.user/) }
    its('stdout') { should match (/roles\/storagetransfer.viewer/) }
  end

  # list_roles
  describe command("forseti explainer list_roles") do
    its('exit_status') { should eq 0 }
    its('stdout') { should match (/roles\/cloudtrace.user/) }
    its('stdout') { should match (/roles\/compute.admin/) }
    its('stdout') { should match (/roles\/storage.objectAdmin/) }
    its('stdout') { should match (/roles\/stackdriver.accounts.viewer/) }
    its('stdout') { should match (/roles\/serviceusage.serviceUsageViewer/) }
    its('stdout') { should match (/roles\/servicemanagement.quotaAdmin/) }
    its('stdout') { should match (/roles\/securitycenter.sourcesEditor/) }
    its('stdout') { should match (/roles\/securitycenter.findingsStateSetter/) }
    its('stdout') { should match (/roles\/securitycenter.findingsEditor/) }
    its('stdout') { should match (/roles\/pubsub.editor/) }
    its('stdout') { should match (/roles\/monitoring.viewer/) }
    its('stdout') { should match (/roles\/container.clusterViewer/) }
    its('stdout') { should match (/roles\/dataflow.worker/) }
    its('stdout') { should match (/roles\/datastore.viewer/) }
  end

  # list_roles --prefix IAM
  describe command("forseti explainer list_roles --prefix roles/iam") do
    its('exit_status') { should eq 0 }
    its('stdout') { should match (/roles\/iam.organizationRoleAdmin/) }
    its('stdout') { should match (/roles\/iam.organizationRoleViewer/) }
    its('stdout') { should match (/roles\/iam.roleAdmin/) }
    its('stdout') { should match (/roles\/iam.roleViewer/) }
    its('stdout') { should match (/roles\/iam.securityAdmin/) }
    its('stdout') { should match (/roles\/iam.securityReviewer/) }
    its('stdout') { should match (/roles\/iam.serviceAccountAdmin/) }
    its('stdout') { should match (/roles\/iam.serviceAccountCreator/) }
    its('stdout') { should match (/roles\/iam.serviceAccountDeleter/) }
    its('stdout') { should match (/roles\/iam.serviceAccountKeyAdmin/) }
    its('stdout') { should match (/roles\/iam.serviceAccountTokenCreator/) }
    its('stdout') { should match (/roles\/iam.serviceAccountUser/) }
    its('stdout') { should match (/roles\/iam.workloadIdentityUser/) }
  end

  # list_roles --prefix storage
  describe command("forseti explainer list_roles --prefix roles/storage") do
    its('exit_status') { should eq 0 }
    its('stdout') { should match (/roles\/storage.admin/) }
    its('stdout') { should match (/roles\/storage.hmacKeyAdmin/) }
    its('stdout') { should match (/roles\/storage.legacyBucketOwner/) }
    its('stdout') { should match (/roles\/storage.legacyBucketReader/) }
    its('stdout') { should match (/roles\/storage.legacyBucketWriter/) }
    its('stdout') { should match (/roles\/storage.legacyObjectOwner/) }
    its('stdout') { should match (/roles\/storage.legacyObjectReader/) }
    its('stdout') { should match (/roles\/storage.objectAdmin/) }
    its('stdout') { should match (/roles\/storage.objectCreator/) }
    its('stdout') { should match (/roles\/storage.objectViewer/) }
    its('stdout') { should match (/roles\/storagetransfer.admin/) }
    its('stdout') { should match (/roles\/storagetransfer.user/) }
    its('stdout') { should match (/roles\/storagetransfer.viewer/) }
  end

  # why_denied permission for org
  describe command("forseti explainer why_denied serviceaccount/#{forseti_server_service_account} organization/#{org_id} --role roles/resourcemanager.organizationAdmin") do
    its('exit_status') { should eq 0 }
    its('stdout') { should match (forseti_server_service_account) }
    its('stdout') { should match (forseti_server_service_account) }
    its('stdout') { should match (/organization\/#{Regexp.quote(org_id)}/) }
    its('stdout') { should match (/roles\/resourcemanager.organizationAdmin/) }
    its('stdout') { should match (/"overgranting": 0/) }
  end

  # why_denied permission for project
  describe command("forseti explainer why_denied serviceaccount/#{forseti_server_service_account} project/#{project_id} --permission storage.buckets.delete") do
    its('exit_status') { should eq 0 }
    its('stdout') { should match (/roles\/cloudmigration.inframanager/) }
    its('stdout') { should match (/roles\/owner/) }
    its('stdout') { should match (/roles\/storage.admin/) }
  end

  # why_granted permission for org
  describe command("forseti explainer why_granted serviceaccount/#{forseti_server_service_account} organization/#{org_id} --permission iam.serviceAccounts.get") do
    its('exit_status') { should eq 0 }
    its('stdout') { should match (/roles\/iam.securityReviewer/) }
  end

  # why_granted permission for project
  describe command("forseti explainer why_granted serviceaccount/#{forseti_server_service_account} project/#{project_id} --permission compute.instances.get") do
    its('exit_status') { should eq 0 }
    its('stdout') { should match (/roles\/compute.networkViewer/) }
  end

  # why_granted role for org
  describe command("forseti explainer why_granted serviceaccount/#{forseti_server_service_account} organization/#{org_id} --role roles/iam.securityReviewer") do
    its('exit_status') { should eq 0 }
    its('stdout') { should match (/organization\/#{Regexp.quote(org_id)}/) }
  end

  # why_granted role for project
  describe command("forseti explainer why_granted serviceaccount/#{forseti_server_service_account} project/#{project_id} --role roles/compute.networkViewer") do
    its('exit_status') { should eq 0 }
    its('stdout') { should match (/organization\/#{Regexp.quote(org_id)}/) }
  end

  # forseti service account should have storage.objects.get as a permissions
  describe command("forseti explainer check_policy project/#{project_id} storage.objects.get serviceAccount/#{forseti_server_service_account}") do
    its('exit_status') { should eq 0 }
    its('stdout') { should match (/\"result\": true/)}
  end

  # cleanup
  describe command("forseti inventory delete #{@inventory_id}") do
    its('exit_status') { should eq 0 }
  end

  describe command("forseti model delete " + random_string) do
    its('exit_status') { should eq 0 }
  end
end
