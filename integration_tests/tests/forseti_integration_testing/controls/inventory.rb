require 'json'
control 'inventory' do

    describe "Inventory" do
        before :context do
            command("forseti inventory purge 0").result
            command("forseti inventory create").result
            command("sudo apt-get -y install mysql-client").result
        end

        describe "Create an inventory" do

            it "should be visible from the command-line" do
                expect(command("forseti inventory list").stdout).to match /SUCCESS/
            end

            it "should be visible in the database" do
                expect(command("mysql -u root --host 127.0.0.1 --database forseti_security --execute \"SELECT COUNT(DISTINCT gcp_inventory.inventory_index_id) FROM gcp_inventory join inventory_index ON inventory_index.id = gcp_inventory.inventory_index_id;\"").stdout).to match /1/
            end

             # it "should be visible in the database" do
             #    expect(command("mysql -u root --host 127.0.0.1 --database forseti_security --execute \"select count(DISTINCT resource_id) from gcp_inventory where category='resource' and resource_type = 'project';\"").stdout).to match /1/
             # end
        end

        describe "List an inventory" do

            it "should be visible from the command-line" do
                expect(command("forseti inventory list").stderr).to eq ""
            end

            it "should be visible in the database" do
                expect(command("mysql -u root --host 127.0.0.1 --database forseti_security --execute \"SELECT COUNT(DISTINCT gcp_inventory.inventory_index_id) FROM gcp_inventory join inventory_index ON inventory_index.id = gcp_inventory.inventory_index_id;\"").stdout).to match /1/
            end
        end

        describe "Get an inventory" do
            let :inventory_id do
                JSON.parse(command("forseti inventory list").stdout).fetch("id")
            end

            it "should be visible from the command-line" do
                expect(command("forseti inventory get #{inventory_id}").stderr).to eq ""
            end

            it "should be visible in the database" do
                expect(command("mysql -u root --host 127.0.0.1 --database forseti_security --execute \"select * from inventory_index where id = #{inventory_id};\"").stdout).to match /1/
            end
        end

        describe "Delete an inventory" do

            # before context do
            #    command("forseti inventory create").result
            # end

            let :inventory_id do
                JSON.parse(command("forseti inventory list").stdout).fetch("id")
            end

            it "should be visible from the command-line" do
                expect(command("forseti inventory delete #{inventory_id}").stderr).to match ""
            end

            it "should be visible in the database" do
                expect(command("mysql -u root --host 127.0.0.1 --database forseti_security --execute \"SELECT COUNT(DISTINCT gcp_inventory.inventory_index_id) FROM gcp_inventory join inventory_index ON inventory_index.id = gcp_inventory.inventory_index_id;\"").stdout).to match /0/
            end
        end

        describe "Purge an inventory" do
            let :inventory_id do
                JSON.parse(command("forseti inventory list").stdout).fetch("id")
            end

            it "should be visible from the command-line" do
                expect(command("forseti inventory purge 0").stdout).to match /purged/
            end

            it "should be visible in the database" do
                expect(command("mysql -u root --host 127.0.0.1 --database forseti_security --execute \"SELECT COUNT(DISTINCT gcp_inventory.inventory_index_id) FROM gcp_inventory join inventory_index ON inventory_index.id = gcp_inventory.inventory_index_id;\"").stdout).to match /0/
            end
        end
    end

    describe "Model" do
        before :context do
            command("forseti inventory create").result
            inventory_id = JSON.parse(command("forseti inventory list").stdout).fetch("id")
            command("forseti model create --inventory_index_id #{inventory_id} model_new").result
            command("sudo apt-get -y install mysql-client").result
        end

        describe "Create and get a model" do

            it "should be visible from the command-line" do
                expect(command("forseti model get model_new").stderr).to eq ""
            end

            it "should be visible in the database" do
                expect(command("mysql -u root --host 127.0.0.1 --database forseti_security --execute \"SELECT count(*) from model where name = 'model_new';\"").stdout).to match /1/
            end
        end

        describe "Use a model" do

            it "should be visible from the command-line" do
                expect(command("forseti model use model_new").stderr).to eq ""
            end
        end

        describe "List a model" do

            it "should be visible from the command-line" do
                expect(command("forseti model list model_new").stderr).to eq ""
            end
        end

        describe "Delete a model" do

            it "should be visible from the command-line" do
                expect(command("forseti model delete model_new").stderr).to eq ""
            end

            it "should be visible in the database" do
                expect(command("mysql -u root --host 127.0.0.1 --database forseti_security --execute \"SELECT count(*) from model where name = 'model_new';\"").stdout).to match /0/
            end

            after(:context) do
                command("forseti inventory purge 0").result
            end
        end
    end

    describe "Explain" do
        before :context do
            command("forseti inventory create").result
            inventory_id = JSON.parse(command("forseti inventory list").stdout).fetch("id")
            command("forseti model create --inventory_index_id #{inventory_id} model_new").result
            command("forseti model use model_new").result
            command("sudo apt-get -y install mysql-client").result
        end

        describe "List members" do

            it "should be visible from the command-line" do
                expect(command("forseti explainer list_members --prefix rdevani").stderr).to eq ""
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

            it "should be visible from the command-line" do
                expect(command("forseti explainer list_roles --prefix roles/iam").stderr).to eq ""
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

            it "should be visible from the command-line" do
                expect(command("forseti explainer list_roles --prefix roles/storage").stderr).to eq ""
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

            it "should be visible from the command-line" do
                expect(command("forseti explainer list_permissions --roles roles/iam.roleAdmin").stderr).to eq ""
            end
        end

        describe "List IAM storage.Admin permissions" do

            it "should be visible from the command-line" do
                expect(command("forseti explainer list_permissions --roles roles/storage.Admin").stdout).to match /firebase.projects.get/
            end

            it "should be visible from the command-line" do
                expect(command("forseti explainer list_permissions --roles roles/storage.Admin").stdout).to match /resourcemanager.projects.get/
            end

            it "should be visible from the command-line" do
                expect(command("forseti explainer list_permissions --roles roles/storage.Admin").stdout).to match /resourcemanager.projects.list/
            end

            it "should be visible from the command-line" do
                expect(command("forseti explainer list_permissions --roles roles/storage.Admin").stdout).to match /storage.buckets.create/
            end

            it "should be visible from the command-line" do
                expect(command("forseti explainer list_permissions --roles roles/storage.Admin").stdout).to match /storage.buckets.delete/
            end

            it "should be visible from the command-line" do
                expect(command("forseti explainer list_permissions --roles roles/storage.Admin").stdout).to match /storage.buckets.get/
            end

            it "should be visible from the command-line" do
                expect(command("forseti explainer list_permissions --roles roles/storage.Admin").stdout).to match /storage.buckets.getIamPolicy/
            end

            it "should be visible from the command-line" do
                expect(command("forseti explainer list_permissions --roles roles/storage.Admin").stdout).to match /storage.buckets.list/
            end

            it "should be visible from the command-line" do
                expect(command("forseti explainer list_permissions --roles roles/storage.Admin").stdout).to match /storage.buckets.setIamPolicy/
            end

            it "should be visible from the command-line" do
                expect(command("forseti explainer list_permissions --roles roles/storage.Admin").stdout).to match /storage.buckets.update/
            end

            it "should be visible from the command-line" do
                expect(command("forseti explainer list_permissions --roles roles/storage.Admin").stdout).to match /storage.objects.create/
            end

            it "should be visible from the command-line" do
                expect(command("forseti explainer list_permissions --roles roles/storage.Admin").stdout).to match /storage.objects.delete/
            end

            it "should be visible from the command-line" do
                expect(command("forseti explainer list_permissions --roles roles/storage.Admin").stdout).to match /storage.objects.get/
            end

            it "should be visible from the command-line" do
                expect(command("forseti explainer list_permissions --roles roles/storage.Admin").stdout).to match /storage.objects.getIamPolicy/
            end

            it "should be visible from the command-line" do
                expect(command("forseti explainer list_permissions --roles roles/storage.Admin").stdout).to match /storage.objects.list/
            end

            it "should be visible from the command-line" do
                expect(command("forseti explainer list_permissions --roles roles/storage.Admin").stdout).to match /storage.objects.setIamPolicy/
            end

            it "should be visible from the command-line" do
                expect(command("forseti explainer list_permissions --roles roles/storage.Admin").stdout).to match /storage.objects.update/
            end

            it "should be visible from the command-line" do
                expect(command("forseti explainer list_permissions --roles roles/storage.Admin").stderr).to eq ""
            end
        end

        describe "List members who has access to IAM storage.Admin role expand groups" do

            it "should be visible from the command-line" do
                expect(command("forseti explainer access_by_authz --role roles/storage.admin --expand_groups").stdout).to match /project\/release-automate-silver/
            end

            it "should be visible from the command-line" do
                expect(command("forseti explainer access_by_authz --role roles/storage.admin --expand_groups").stdout).to match /serviceaccount\/project-factory-22907@release-automate-silver.iam.gserviceaccount.com/
            end

            it "should be visible from the command-line" do
                expect(command("forseti explainer access_by_authz --role roles/storage.admin --expand_groups").stderr).to eq ""
            end
        end

        describe "List members who has access to IAM storage.Admin role" do

            it "should be visible from the command-line" do
                expect(command("forseti explainer access_by_authz --role roles/storage.admin").stdout).to match /project\/release-automate-silver/
            end

            it "should be visible from the command-line" do
                expect(command("forseti explainer access_by_authz --role roles/storage.admin").stdout).to match /serviceaccount\/project-factory-22907@release-automate-silver.iam.gserviceaccount.com/
            end

            it "should be visible from the command-line" do
                expect(command("forseti explainer access_by_authz --role roles/storage.admin").stderr).to eq ""
            end
        end

        describe "List members who have relation to storage.bucket.delete permission" do

            it "should be visible from the command-line" do
                expect(command("forseti explainer access_by_authz --permission storage.buckets.delete --expand_groups").stdout).to match /project\/integration-1-a26b/
            end

            it "should be visible from the command-line" do
                expect(command("forseti explainer access_by_authz --permission storage.buckets.delete --expand_groups").stdout).to match /project\/release-automate-silver/
            end

            it "should be visible from the command-line" do
                expect(command("forseti explainer access_by_authz --permission storage.buckets.delete").stdout).to match /serviceaccount\/158866727632@cloudservices.gserviceaccount.com/
            end

            it "should be visible from the command-line" do
                expect(command("forseti explainer access_by_authz --permission storage.buckets.delete").stdout).to match /serviceaccount\/74120606973@cloudservices.gserviceaccount.com/
            end

            it "should be visible from the command-line" do
                expect(command("forseti explainer access_by_authz --permission storage.buckets.delete").stdout).to match /serviceaccount\/84605163300-compute@developer.gserviceaccount.com/
            end

            it "should be visible from the command-line" do
                expect(command("forseti explainer access_by_authz --permission storage.buckets.delete").stdout).to match /serviceaccount\/84605163300@cloudservices.gserviceaccount.com/
            end

            it "should be visible from the command-line" do
                expect(command("forseti explainer access_by_authz --permission storage.buckets.delete").stdout).to match /serviceaccount\/project-factory-22907@release-automate-silver.iam.gserviceaccount.com/
            end

            it "should be visible from the command-line" do
                expect(command("forseti explainer access_by_authz --permission storage.buckets.delete").stderr).to eq ""
            end
        end

        describe "List members who have relation to storage.bucket.delete permission expand groups" do

            it "should be visible from the command-line" do
                expect(command("forseti explainer access_by_authz --permission storage.buckets.delete --expand_groups").stdout).to match /project\/integration-1-a26b/
            end

            it "should be visible from the command-line" do
                expect(command("forseti explainer access_by_authz --permission storage.buckets.delete --expand_groups").stdout).to match /project\/release-automate-silver/
            end

            it "should be visible from the command-line" do
                expect(command("forseti explainer access_by_authz --permission storage.buckets.delete --expand_groups").stdout).to match /serviceaccount\/158866727632@cloudservices.gserviceaccount.com/
            end

            it "should be visible from the command-line" do
                expect(command("forseti explainer access_by_authz --permission storage.buckets.delete --expand_groups").stdout).to match /serviceaccount\/74120606973@cloudservices.gserviceaccount.com/
            end

            it "should be visible from the command-line" do
                expect(command("forseti explainer access_by_authz --permission storage.buckets.delete --expand_groups").stdout).to match /serviceaccount\/84605163300-compute@developer.gserviceaccount.com/
            end

            it "should be visible from the command-line" do
                expect(command("forseti explainer access_by_authz --permission storage.buckets.delete --expand_groups").stdout).to match /serviceaccount\/84605163300@cloudservices.gserviceaccount.com/
            end

            it "should be visible from the command-line" do
                expect(command("forseti explainer access_by_authz --permission storage.buckets.delete --expand_groups").stdout).to match /serviceaccount\/project-factory-22907@release-automate-silver.iam.gserviceaccount.com/
            end

            it "should be visible from the command-line" do
                expect(command("forseti explainer access_by_authz --permission storage.buckets.delete --expand_groups").stderr).to eq ""
            end

            after(:context) do
                command("forseti inventory purge 0").result
                command("forseti model delete model_new").result
            end
        end
    end
end
