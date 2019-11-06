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
control 'explain' do

    # Assertions are repeated here instead of using regex to improve readability
    describe "Explain" do
        before :context do
            command("forseti inventory purge 0").result
            command("forseti inventory create").result

            # This variable cannot be used after all the inventories have been purged.
            @inventory_id = JSON.parse(command("forseti inventory list").stdout).fetch("id")
            command("forseti model create --inventory_index_id #{@inventory_id} model_explain").result
            command("forseti model use model_explain").result
        end

        describe "Successful inventory creation" do

            it "should be visible from the command-line" do
                expect(command("forseti inventory list").stdout).to match /SUCCESS/
            end
        end

        describe "List members" do

            it "should be visible from the command-line" do
                expect(command("forseti explainer list_members --prefix rdevani").stdout).to match /memberName/
            end
        end

        describe "List all members" do

            it "should be visible from the command-line" do
                expect(command("forseti explainer list_members").stdout).to match /projecteditor\/release-automate-silver/
            end

            it "should be visible from the command-line" do
                expect(command("forseti explainer list_members").stdout).to match /projectowner\/release-automate-silver/
            end

            it "should be visible from the command-line" do
                expect(command("forseti explainer list_members").stdout).to match /projectviewer\/release-automate-silver/
            end

            it "should be visible from the command-line" do
                expect(command("forseti explainer list_members").stdout).to match /projecteditor\/release-automate-silver/
            end
        end

        describe "List all roles" do

            it "should be visible from the command-line" do
                expect(command("forseti explainer list_roles").stdout).to match /roles\/cloudtrace.user/
            end

            it "should be visible from the command-line" do
                expect(command("forseti explainer list_roles").stdout).to match /roles\/compute.admin/
            end

            it "should be visible from the command-line" do
                expect(command("forseti explainer list_roles").stdout).to match /roles\/storage.objectAdmin/
            end

            it "should be visible from the command-line" do
                expect(command("forseti explainer list_roles").stdout).to match /roles\/stackdriver.accounts.viewer/
            end

            it "should be visible from the command-line" do
                expect(command("forseti explainer list_roles").stdout).to match /roles\/serviceusage.serviceUsageViewer/
            end

            it "should be visible from the command-line" do
                expect(command("forseti explainer list_roles").stdout).to match /roles\/servicemanagement.quotaAdmin/
            end

            it "should be visible from the command-line" do
                expect(command("forseti explainer list_roles").stdout).to match /roles\/securitycenter.sourcesEditor/
            end

            it "should be visible from the command-line" do
                expect(command("forseti explainer list_roles").stdout).to match /roles\/securitycenter.findingsStateSetter/
            end

            it "should be visible from the command-line" do
                expect(command("forseti explainer list_roles").stdout).to match /roles\/securitycenter.findingsEditor/
            end

            it "should be visible from the command-line" do
                expect(command("forseti explainer list_roles").stdout).to match /roles\/pubsub.editor/
            end

            it "should be visible from the command-line" do
                expect(command("forseti explainer list_roles").stdout).to match /roles\/monitoring.viewer/
            end

            it "should be visible from the command-line" do
                expect(command("forseti explainer list_roles").stdout).to match /roles\/container.clusterViewer/
            end

            it "should be visible from the command-line" do
                expect(command("forseti explainer list_roles").stdout).to match /roles\/dataflow.worker/
            end

            it "should be visible from the command-line" do
                expect(command("forseti explainer list_roles").stdout).to match /roles\/datastore.viewer/
            end
        end

        describe "List IAM roles" do

            it "should be visible from the command-line" do
                expect(command("forseti explainer list_roles --prefix roles/iam").stdout).to match /roles\/iam.organizationRoleAdmin/
            end

            it "should be visible from the command-line" do
                expect(command("forseti explainer list_roles --prefix roles/iam").stdout).to match /roles\/iam.organizationRoleViewer/
            end

            it "should be visible from the command-line" do
                expect(command("forseti explainer list_roles --prefix roles/iam").stdout).to match /roles\/iam.roleAdmin/
            end

            it "should be visible from the command-line" do
                expect(command("forseti explainer list_roles --prefix roles/iam").stdout).to match /roles\/iam.roleViewer/
            end

            it "should be visible from the command-line" do
                expect(command("forseti explainer list_roles --prefix roles/iam").stdout).to match /roles\/iam.securityAdmin/
            end

            it "should be visible from the command-line" do
                expect(command("forseti explainer list_roles --prefix roles/iam").stdout).to match /roles\/iam.securityReviewer/
            end

            it "should be visible from the command-line" do
                expect(command("forseti explainer list_roles --prefix roles/iam").stdout).to match /roles\/iam.serviceAccountAdmin/
            end

            it "should be visible from the command-line" do
                expect(command("forseti explainer list_roles --prefix roles/iam").stdout).to match /roles\/iam.serviceAccountCreator/
            end

            it "should be visible from the command-line" do
                expect(command("forseti explainer list_roles --prefix roles/iam").stdout).to match /roles\/iam.serviceAccountDeleter/
            end

            it "should be visible from the command-line" do
                expect(command("forseti explainer list_roles --prefix roles/iam").stdout).to match /roles\/iam.serviceAccountKeyAdmin/
            end

            it "should be visible from the command-line" do
                expect(command("forseti explainer list_roles --prefix roles/iam").stdout).to match /roles\/iam.serviceAccountTokenCreator/
            end

            it "should be visible from the command-line" do
                expect(command("forseti explainer list_roles --prefix roles/iam").stdout).to match /roles\/iam.serviceAccountUser/
            end

            it "should be visible from the command-line" do
                expect(command("forseti explainer list_roles --prefix roles/iam").stdout).to match /roles\/iam.workloadIdentityUser/
            end
        end

        describe "List Storage roles" do

            it "should be visible from the command-line" do
                expect(command("forseti explainer list_roles --prefix roles/storage").stdout).to match /roles\/storage.admin/
            end

            it "should be visible from the command-line" do
                expect(command("forseti explainer list_roles --prefix roles/storage").stdout).to match /roles\/storage.hmacKeyAdmin/
            end

            it "should be visible from the command-line" do
                expect(command("forseti explainer list_roles --prefix roles/storage").stdout).to match /roles\/storage.legacyBucketOwner/
            end

            it "should be visible from the command-line" do
                expect(command("forseti explainer list_roles --prefix roles/storage").stdout).to match /roles\/storage.legacyBucketReader/
            end

            it "should be visible from the command-line" do
                expect(command("forseti explainer list_roles --prefix roles/storage").stdout).to match /roles\/storage.legacyBucketWriter/
            end

            it "should be visible from the command-line" do
                expect(command("forseti explainer list_roles --prefix roles/storage").stdout).to match /roles\/storage.legacyObjectOwner/
            end

            it "should be visible from the command-line" do
                expect(command("forseti explainer list_roles --prefix roles/storage").stdout).to match /roles\/storage.legacyObjectReader/
            end

            it "should be visible from the command-line" do
                expect(command("forseti explainer list_roles --prefix roles/storage").stdout).to match /roles\/storage.objectAdmin/
            end

            it "should be visible from the command-line" do
                expect(command("forseti explainer list_roles --prefix roles/storage").stdout).to match /roles\/storage.objectCreator/
            end

            it "should be visible from the command-line" do
                expect(command("forseti explainer list_roles --prefix roles/storage").stdout).to match /roles\/storage.objectViewer/
            end

            it "should be visible from the command-line" do
                expect(command("forseti explainer list_roles --prefix roles/storage").stdout).to match /roles\/storagetransfer.admin/
            end

            it "should be visible from the command-line" do
                expect(command("forseti explainer list_roles --prefix roles/storage").stdout).to match /roles\/storagetransfer.user/
            end

            it "should be visible from the command-line" do
                expect(command("forseti explainer list_roles --prefix roles/storage").stdout).to match /roles\/storagetransfer.viewer/
            end
        end

        describe "List IAM roleAdmin permissions" do

            it "should be visible from the command-line" do
                expect(command("forseti explainer list_permissions --roles roles/iam.roleAdmin").stdout).to match /roles.create/
            end

            it "should be visible from the command-line" do
                expect(command("forseti explainer list_permissions --roles roles/iam.roleAdmin").stdout).to match /roles.delete/
            end

            it "should be visible from the command-line" do
                expect(command("forseti explainer list_permissions --roles roles/iam.roleAdmin").stdout).to match /roles.get/
            end

            it "should be visible from the command-line" do
                expect(command("forseti explainer list_permissions --roles roles/iam.roleAdmin").stdout).to match /roles.list/
            end

            it "should be visible from the command-line" do
                expect(command("forseti explainer list_permissions --roles roles/iam.roleAdmin").stdout).to match /roles.undelete/
            end

            it "should be visible from the command-line" do
                expect(command("forseti explainer list_permissions --roles roles/iam.roleAdmin").stdout).to match /roles.update/
            end

            it "should be visible from the command-line" do
                expect(command("forseti explainer list_permissions --roles roles/iam.roleAdmin").stdout).to match /resourcemanager.projects.get/
            end

            it "should be visible from the command-line" do
                expect(command("forseti explainer list_permissions --roles roles/iam.roleAdmin").stdout).to match /resourcemanager.projects.getIamPolicy/
            end
        end

        describe "List members who has access to IAM storage.Admin role expand groups" do

            it "should be visible from the command-line" do
                expect(command("forseti explainer access_by_authz --role roles/storage.admin --expand_groups").stdout).to match /project\/release-automate-silver/
            end

            it "should be visible from the command-line" do
                expect(command("forseti explainer access_by_authz --role roles/storage.admin --expand_groups").stdout).to match /serviceaccount\/project-factory-22907@release-automate-silver.iam.gserviceaccount.com/
            end
        end

        describe "List permissions in storage role" do

            it "should be visible from the command-line" do
                expect(command("forseti explainer access_by_authz --permission iam.serviceAccounts.get").stdout).to match /roles\/editor/
            end

            it "should be visible from the command-line" do
                expect(command("forseti explainer access_by_authz --permission iam.serviceAccounts.get").stdout).to match /project\/release-automate-silver/
            end

            it "should be visible from the command-line" do
                expect(command("forseti explainer access_by_authz --permission iam.serviceAccounts.get").stdout).to match /serviceaccount\/project-factory-22907@release-automate-silver.iam.gserviceaccount.com/
            end
        end

        describe "List members who has access to IAM storage.Admin role" do

            it "should be visible from the command-line" do
                expect(command("forseti explainer access_by_authz --role roles/storage.admin").stdout).to match /project\/release-automate-silver/
            end

            it "should be visible from the command-line" do
                expect(command("forseti explainer access_by_authz --role roles/storage.admin").stdout).to match /serviceaccount\/project-factory-22907@release-automate-silver.iam.gserviceaccount.com/
            end
        end

        describe "List members who have relation to storage.bucket.delete permission" do

            it "should be visible from the command-line" do
                expect(command("forseti explainer access_by_authz --permission storage.buckets.delete --expand_groups").stdout).to match /project\/release-automate-silver/
            end

            it "should be visible from the command-line" do
                expect(command("forseti explainer access_by_authz --permission storage.buckets.delete").stdout).to match /serviceaccount\/project-factory-22907@release-automate-silver.iam.gserviceaccount.com/
            end
        end

        describe "List members who have relation to storage.bucket.delete permission expand groups" do

            it "should be visible from the command-line" do
                expect(command("forseti explainer access_by_authz --permission storage.buckets.delete --expand_groups").stdout).to match /project\/release-automate-silver/
            end

            it "should be visible from the command-line" do
                expect(command("forseti explainer access_by_authz --permission storage.buckets.delete --expand_groups").stdout).to match /serviceaccount\/project-factory-22907@release-automate-silver.iam.gserviceaccount.com/
            end

            after(:context) do
                command("forseti inventory purge 0").result
                command("forseti model delete model_explain").result
            end
        end
    end
end

