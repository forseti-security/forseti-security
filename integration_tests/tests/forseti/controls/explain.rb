# Copyright 2018 Google LLC
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
control "explain" do
  before :context do
    command("forseti inventory purge 0").result
    command("forseti inventory create").result
    inventory_id = JSON.parse(command("forseti inventory list").stdout).fetch("id")
    command("forseti model create --inventory_index_id #{inventory_id} model_new").result
    command("forseti model use model_new").result
  end

  describe command("forseti explainer list_members --prefix rdevani") do
    its('exit_status') { should eq 0 }
    its('stdout') { should match (/memberName/) }
  end

  describe command("forseti explainer list_members") do
    its('exit_status') { should eq 0 }
    its('stdout') { should match (/projecteditor\/release-automate-silver/) }
    its('stdout') { should match (/projectowner\/release-automate-silver/) }
    its('stdout') { should match (/projectviewer\/release-automate-silver/) }
    its('stdout') { should match (/serviceaccount\/84605163300-compute@developer.gserviceaccount.com"/) }
    its('stdout') { should match (/serviceaccount\/84605163300@cloudservices.gserviceaccount.com/) }
    its('stdout') { should match (/serviceaccount\/74120606973@cloudservices.gserviceaccount.com"/) }
    its('stdout') { should match (/serviceaccount\/74120606973@cloudservices.gserviceaccount.com/) }
    its('stdout') { should match (/serviceaccount\/158866727632-compute@developer.gserviceaccount.com/) }
    its('stdout') { should match (/serviceaccount\/158866727632@cloudservices.gserviceaccount.com/) }
  end

  describe command("forseti explainer list_roles") do
    its('exit_status') { should eq 0 }
    its('stdout') { should match (/projecteditor\/release-automate-silver/) }
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

  describe command("forseti explainer list_permissions --roles roles/iam.roleAdmin") do
    its('exit_status') { should eq 0 }
    its('stdout') { should match (/roles.create/) }
    its('stdout') { should match (/roles.delete/) }
    its('stdout') { should match (/roles.get/) }
    its('stdout') { should match (/roles.list/) }
    its('stdout') { should match (/roles.undelete/) }
    its('stdout') { should match (/roles.update/) }
    its('stdout') { should match (/resourcemanager.projects.get/) }
    its('stdout') { should match (/resourcemanager.projects.getIamPolicy/) }
  end

  describe command("forseti explainer list_permissions --roles roles/storage.Admin") do
    its('exit_status') { should eq 0 }
    its('stdout') { should match (/firebase.projects.get/) }
    its('stdout') { should match (/resourcemanager.projects.get/) }
    its('stdout') { should match (/resourcemanager.projects.list/) }
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

  describe command("forseti explainer access_by_authz --role roles/storage.admin --expand_groups") do
    its('exit_status') { should eq 0 }
    its('stdout') { should match (/project\/release-automate-silver/) }
    its('stdout') { should match (/serviceaccount\/project-factory-22907@release-automate-silver.iam.gserviceaccount.com/) }
  end

  describe command("forseti explainer access_by_authz --permission iam.serviceAccounts.get") do
    its('exit_status') { should eq 0 }
    its('stdout') { should match (/roles\/editor/) }
    its('stdout') { should match (/project\/release-automate-silver/) }
    its('stdout') { should match (/serviceaccount\/project-factory-22907@release-automate-silver.iam.gserviceaccount.com/) }
    its('stdout') { should match (/serviceaccount\/158866727632@cloudservices.gserviceaccount.com/) }
  end

  describe command("forseti explainer access_by_authz --role roles/storage.admin") do
    its('exit_status') { should eq 0 }
    its('stdout') { should match (/project\/release-automate-silver/) }
    its('stdout') { should match (/serviceaccount\/project-factory-22907@release-automate-silver.iam.gserviceaccount.com/) }
  end

  describe command("forseti explainer access_by_authz --permission storage.buckets.delete --expand_groups") do
    its('exit_status') { should eq 0 }
    its('stdout') { should match (/project\/integration-1-a26b/) }
    its('stdout') { should match (/project\/release-automate-silver/) }
  end

  describe command("forseti explainer access_by_authz --permission storage.buckets.delete") do
    its('exit_status') { should eq 0 }
    its('stdout') { should match (/serviceaccount\/158866727632@cloudservices.gserviceaccount.com/) }
    its('stdout') { should match (/serviceaccount\/74120606973@cloudservices.gserviceaccount.com/) }
    its('stdout') { should match (/serviceaccount\/84605163300-compute@developer.gserviceaccount.com/) }
    its('stdout') { should match (/serviceaccount\/84605163300@cloudservices.gserviceaccount.com/) }
    its('stdout') { should match (/serviceaccount\/project-factory-22907@release-automate-silver.iam.gserviceaccount.com/) }
  end

  describe command("forseti explainer access_by_authz --permission storage.buckets.delete --expand_groups") do
    its('exit_status') { should eq 0 }
    its('stdout') { should match (/project\/integration-1-a26b/) }
    its('stdout') { should match (/project\/release-automate-silver/) }
    its('stdout') { should match (/serviceaccount\/158866727632@cloudservices.gserviceaccount.com/) }
    its('stdout') { should match (/serviceaccount\/74120606973@cloudservices.gserviceaccount.com/) }
    its('stdout') { should match (/serviceaccount\/84605163300-compute@developer.gserviceaccount.com/) }
    its('stdout') { should match (/serviceaccount\/84605163300@cloudservices.gserviceaccount.com/) }
    its('stdout') { should match (/serviceaccount\/project-factory-22907@release-automate-silver.iam.gserviceaccount.com/) }
  end

  after(:context) do
    command("forseti inventory purge 0").result
    command("forseti model delete model_new").result
  end
end
