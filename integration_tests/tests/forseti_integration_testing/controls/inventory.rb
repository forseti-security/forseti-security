require 'json'
control 'inventory' do

     describe "Create an inventory" do
        subject do
            command("forseti inventory list")
        end

        before do
            command("forseti inventory create").result
        end

        its("stdout") { should match /SUCCESS/}

        after do
            command("forseti inventory purge 0").result
        end
    end

    describe "Create an inventory and check database" do
        subject do
            command("mysql -u root --host 127.0.0.1 --database forseti_security --execute \"select count(DISTINCT resource_id) from gcp_inventory where category='resource' and resource_type = 'project';\"")
        end

        before(:context) do
            command("forseti inventory create").result
            command("sudo apt-get -y install mysql-client").result
        end

        # its("stdout") { should match "2" }
        its("stderr") { should eq ""}

        after do
            command("forseti inventory purge 0").result
        end
    end

    describe "Purge inventory" do
        subject do
            command("forseti inventory purge 0")
        end

        before do
            command("forseti inventory create").result
        end

        its("stdout") { should match /purged/ }

    end

    describe "List inventory" do
        subject do
            command("forseti inventory list")
        end

        before do
            command("forseti inventory create").result
        end

        its("stderr") { should eq ""}

        after do
            command("forseti inventory purge 0").result
        end
    end

    describe "Get inventory" do
        subject do
            command("forseti inventory get #{inventory_id}")
        end

        let :inventory_id do
            command("forseti inventory create").result
            JSON.parse(command("forseti inventory list").stdout).fetch("id")
        end

        its("stderr") { should eq ""}

        after do
            command("forseti inventory purge 0").result
        end
    end

    describe "Delete inventory" do
        subject do
            command("forseti inventory delete #{inventory_id}")
        end

        let :inventory_id do
            command("forseti inventory create").result
            JSON.parse(command("forseti inventory list").stdout).fetch("id")
        end

        its("stderr") { should eq ""}

    end

    describe "Create inventory and model" do
        subject do
            command("forseti model create --inventory_index_id #{inventory_id} test_model")
        end

        let :inventory_id do
            command("forseti inventory create").result
            JSON.parse(command("forseti inventory list").stdout).fetch("id")
        end

        its("stdout") { should match /SUCCESS/ }

        after do
            command("forseti inventory purge 0").result
            command("forseti model delete test_model").result
        end
    end

    describe "Get model" do
        subject do
            command("forseti model get model_new")
        end

        before(:context) do
            command("forseti inventory create").result
            inventory_id = JSON.parse(command("forseti inventory list").stdout).fetch("id")
            command("forseti model create --inventory_index_id #{inventory_id} model_new").result
        end

        its("stderr") { should eq ""}

        after do
            command("forseti inventory purge 0").result
            command("forseti model delete model_new").result
        end
    end

    describe "List model" do
        subject do
            command("forseti model list")
        end

        before(:context) do
            command("forseti inventory create").result
            inventory_id = JSON.parse(command("forseti inventory list").stdout).fetch("id")
            command("forseti model create --inventory_index_id #{inventory_id} model_new").result
        end

        its("stdout") { should match /SUCCESS/ }

        after do
            command("forseti inventory purge 0").result
            command("forseti model delete model_new").result
        end
    end

    describe "Delete model" do
        subject do
            command("forseti model delete model_new")
        end

        before(:context) do
            command("forseti inventory create").result
            inventory_id = JSON.parse(command("forseti inventory list").stdout).fetch("id")
            command("forseti model create --inventory_index_id #{inventory_id} model_new").result
        end

        its("stdout") { should match /SUCCESS/ }

        after do
            command("forseti inventory purge 0").result
        end
    end

    describe "List members Explainer" do
        subject do
            command("forseti explainer list_members --prefix rdevani")
        end

        before(:context) do
            command("forseti inventory create").result
            inventory_id = JSON.parse(command("forseti inventory list").stdout).fetch("id")
            command("forseti model create --inventory_index_id #{inventory_id} model_new").result
            command("forseti model use model_new").result
        end

        its("stderr") { should eq ""}

        after do
            command("forseti inventory purge 0").result
            command("forseti model delete model_new")
        end
    end

    describe "List IAM roles Explainer" do
        subject do
            command("forseti explainer list_roles --prefix roles/iam")
        end

        before(:context) do
            command("forseti inventory create").result
            inventory_id = JSON.parse(command("forseti inventory list").stdout).fetch("id")
            command("forseti model create --inventory_index_id #{inventory_id} model_new").result
            command("forseti model use model_new").result
        end

        its("stdout") { should match /roles\/iam.organizationRoleAdmin/ }
        its("stdout") { should match /roles\/iam.organizationRoleViewer/ }
        its("stdout") { should match /roles\/iam.roleAdmin/ }
        its("stdout") { should match /roles\/iam.roleViewer/ }
        its("stdout") { should match /roles\/iam.securityAdmin/ }
        its("stdout") { should match /roles\/iam.securityReviewer/ }
        its("stdout") { should match /roles\/iam.serviceAccountAdmin/ }
        its("stdout") { should match /roles\/iam.serviceAccountCreator/ }
        its("stdout") { should match /roles\/iam.serviceAccountDeleter/ }
        its("stdout") { should match /roles\/iam.serviceAccountKeyAdmin/ }
        its("stdout") { should match /roles\/iam.serviceAccountTokenCreator/ }
        its("stdout") { should match /roles\/iam.serviceAccountUser/ }
        its("stdout") { should match /roles\/iam.workloadIdentityUser/ }
        its("stderr") { should eq ""}

        after(:context) do
            command("forseti inventory purge 0").result
            command("forseti model delete model_new")
        end
    end


    describe "List Storage roles Explainer" do
        subject do
            command("forseti explainer list_roles --prefix roles/storage")
        end

        before(:context) do
            command("forseti inventory create").result
            inventory_id = JSON.parse(command("forseti inventory list").stdout).fetch("id")
            command("forseti model create --inventory_index_id #{inventory_id} model_new").result
            command("forseti model use model_new").result
        end

        its("stdout") { should match /roles\/storage.admin/ }
        its("stdout") { should match /roles\/storage.hmacKeyAdmin/ }
        its("stdout") { should match /roles\/storage.legacyBucketOwner/ }
        its("stdout") { should match /roles\/storage.legacyBucketReader/ }
        its("stdout") { should match /roles\/storage.legacyBucketWriter/ }
        its("stdout") { should match /roles\/storage.legacyObjectOwner/ }
        its("stdout") { should match /roles\/storage.legacyObjectReader/ }
        its("stdout") { should match /roles\/storage.objectAdmin/ }
        its("stdout") { should match /roles\/storage.objectCreator/ }
        its("stdout") { should match /roles\/storage.objectViewer/ }
        its("stdout") { should match /roles\/storagetransfer.admin/ }
        its("stdout") { should match /roles\/storagetransfer.user/ }
        its("stdout") { should match /roles\/storagetransfer.viewer/ }
        its("stderr") { should eq ""}

        after do
            command("forseti inventory purge 0").result
            command("forseti model delete model_new")
        end
    end

    describe "List IAM roleAdmin permissions Explainer" do
        subject do
            command("forseti explainer list_permissions --roles roles/iam.roleAdmin")
        end

        before(:context) do
            command("forseti inventory create").result
            inventory_id = JSON.parse(command("forseti inventory list").stdout).fetch("id")
            command("forseti model create --inventory_index_id #{inventory_id} model_new").result
            command("forseti model use model_new").result
        end

        its("exit_status") { should eq 0 }
        its("stdout") { should match /roles.create/ }
        its("stdout") { should match /roles.delete/ }
        its("stdout") { should match /roles.get/ }
        its("stdout") { should match /roles.list/ }
        its("stdout") { should match /roles.undelete/ }
        its("stdout") { should match /roles.update/ }
        its("stdout") { should match /resourcemanager.projects.get/ }
        its("stdout") { should match /resourcemanager.projects.getIamPolicy/ }
        its("stderr") { should eq ""}

        after(:context) do
            command("forseti inventory purge 0").result
            command("forseti model delete model_new")
        end
    end

    describe "List IAM storage.Admin permissions Explainer" do
        subject do
            command("forseti explainer list_permissions --roles roles/storage.Admin")
        end

        before(:context) do
            command("forseti inventory create").result
            inventory_id = JSON.parse(command("forseti inventory list").stdout).fetch("id")
            command("forseti model create --inventory_index_id #{inventory_id} model_new").result
            command("forseti model use model_new").result
        end

        its("exit_status") { should eq 0 }
        its("stdout") { should match /firebase.projects.get/ }
        its("stdout") { should match /resourcemanager.projects.get/ }
        its("stdout") { should match /resourcemanager.projects.list/ }
        its("stdout") { should match /storage.buckets.create/}
        its("stdout") { should match /storage.buckets.delete/}
        its("stdout") { should match /storage.buckets.get/}
        its("stdout") { should match /storage.buckets.getIamPolicy/ }
        its("stdout") { should match /storage.buckets.list/}
        its("stdout") { should match /storage.buckets.setIamPolicy/}
        its("stdout") { should match /storage.buckets.update/ }
        its("stdout") { should match /storage.objects.create/ }
        its("stdout") { should match /storage.objects.delete/ }
        its("stdout") { should match /storage.objects.get/ }
        its("stdout") { should match /storage.objects.getIamPolicy/ }
        its("stdout") { should match /storage.objects.list/ }
        its("stdout") { should match /storage.objects.setIamPolicy/ }
        its("stdout") { should match /storage.objects.update/ }

        after(:context) do
            command("forseti inventory purge 0").result
            command("forseti model delete model_new")
        end
    end

    describe "List members who has access to IAM storage.Admin role expand groups Explainer" do
        subject do
            command("forseti explainer access_by_authz --role roles/storage.admin --expand_groups ")
        end

        before(:context) do
            command("forseti inventory create").result
            inventory_id = JSON.parse(command("forseti inventory list").stdout).fetch("id")
            command("forseti model create --inventory_index_id #{inventory_id} model_new").result
            command("forseti model use model_new").result
        end

        its("exit_status") { should eq 0 }
        its("stdout") { should match /project\/release-automate-silver/ }
        its("stdout") { should match /serviceaccount\/project-factory-22907@release-automate-silver.iam.gserviceaccount.com/ }

        after(:context) do
            command("forseti inventory purge 0").result
            command("forseti model delete model_new")
        end
    end

    describe "List members who has access to IAM storage.Admin role Explainer" do
        subject do
            command("forseti explainer access_by_authz --role roles/storage.admin")
        end

        before(:context) do
            command("forseti inventory create").result
            inventory_id = JSON.parse(command("forseti inventory list").stdout).fetch("id")
            command("forseti model create --inventory_index_id #{inventory_id} model_new").result
            command("forseti model use model_new").result
        end

        its("exit_status") { should eq 0 }
        its("stdout") { should match /project\/release-automate-silver/ }
        its("stdout") { should match /serviceaccount\/project-factory-22907@release-automate-silver.iam.gserviceaccount.com/ }

        after(:context) do
            command("forseti inventory purge 0").result
            command("forseti model delete model_new")
        end
    end

    describe "List members who have relation to storage.bucket.delete permission Explainer" do
        subject do
            command("forseti explainer access_by_authz --permission storage.buckets.delete")
        end

        before(:context) do
            command("forseti inventory create").result
            inventory_id = JSON.parse(command("forseti inventory list").stdout).fetch("id")
            command("forseti model create --inventory_index_id #{inventory_id} model_new").result
            command("forseti model use model_new").result
        end

        its("exit_status") { should eq 0 }
        its("stdout") { should match /project\/integration-1-a26b/ }
        its("stdout") { should match /project\/release-automate-silver/ }
        its("stdout") { should match /serviceaccount\/158866727632-compute@developer.gserviceaccount.com/ }
        its("stdout") { should match /serviceaccount\/158866727632@cloudservices.gserviceaccount.com/ }
        its("stdout") { should match /serviceaccount\/74120606973@cloudservices.gserviceaccount.com/ }
        its("stdout") { should match /serviceaccount\/74120606973-compute@developer.gserviceaccount.com/ }
        its("stdout") { should match /serviceaccount\/84605163300-compute@developer.gserviceaccount.com/ }
        its("stdout") { should match /serviceaccount\/84605163300@cloudservices.gserviceaccount.com/ }
        its("stdout") { should match /serviceaccount\/project-factory-22907@release-automate-silver.iam.gserviceaccount.com/ }

        after(:context) do
            command("forseti inventory purge 0").result
            command("forseti model delete model_new")
        end
    end

    describe "List members who have relation to storage.bucket.delete permission expand groups Explainer" do
        subject do
            command("forseti explainer access_by_authz --permission storage.buckets.delete --expand_groups")
        end

        before(:context) do
            command("forseti inventory create").result
            inventory_id = JSON.parse(command("forseti inventory list").stdout).fetch("id")
            command("forseti model create --inventory_index_id #{inventory_id} model_new").result
            command("forseti model use model_new").result
        end

        its("exit_status") { should eq 0 }
        its("stdout") { should match /project\/integration-1-a26b/ }
        its("stdout") { should match /project\/release-automate-silver/ }
        its("stdout") { should match /serviceaccount\/158866727632-compute@developer.gserviceaccount.com/ }
        its("stdout") { should match /serviceaccount\/158866727632@cloudservices.gserviceaccount.com/ }
        its("stdout") { should match /serviceaccount\/74120606973@cloudservices.gserviceaccount.com/ }
        its("stdout") { should match /serviceaccount\/74120606973-compute@developer.gserviceaccount.com/ }
        its("stdout") { should match /serviceaccount\/84605163300-compute@developer.gserviceaccount.com/ }
        its("stdout") { should match /serviceaccount\/84605163300@cloudservices.gserviceaccount.com/ }
        its("stdout") { should match /serviceaccount\/project-factory-22907@release-automate-silver.iam.gserviceaccount.com/ }

        after(:context) do
            command("forseti inventory purge 0").result
            command("forseti model delete model_new")
        end
    end
end
