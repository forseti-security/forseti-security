
require 'json'
control 'model' do

    describe "Model" do
        before :context do
            command("forseti inventory purge 0").result
            command("forseti inventory create").result

            # This variable cannot be used after all the inventories have been purged..
            @inventory_id = JSON.parse(command("forseti inventory list").stdout).fetch("id")
            command("forseti model create --inventory_index_id #{@inventory_id} model_new").result
            command("forseti model use model_new").result
        end

        describe "Create and get a model" do

            it "should be visible from the command-line" do
                expect(command("forseti model get model_new").stderr).to eq ""
            end

            it "should be visible from the command-line" do
                expect(command("forseti model get model_new").stdout).to match /model_new/
            end

            it "should be visible from the command-line" do
                expect(command("forseti model get model_new").stdout).to match /SUCCESS/
            end


            it "should be visible in the database" do
                expect(command("mysql -u root --host 127.0.0.1 --database forseti_security --execute \"select state from model where name = 'model_new';\"").stdout).to match /PARTIAL_SUCCESS/
            end
        end

        describe "List a model" do

            it "should be visible from the command-line" do
                expect(command("forseti model list model_new").stderr).to eq ""
            end

            it "should be visible from the command-line" do
                expect(command("forseti model list model_new").stderr).to match /SUCCESS/
            end
        end

        describe "Use a model" do

            it "should be visible from the command-line" do
                expect(command("forseti model use model_new").stderr).to eq ""
            end
        end

        describe "Delete a model" do

            before :context do
                command("forseti model create --inventory_index_id #{@inventory_id} model_test").result
                command("forseti model use model_test").result
            end

            it "should be visible from the command-line" do
                expect(command("forseti model delete model_test").stderr).to eq ""
            end

            it "should be visible from the command-line" do
                expect(command("forseti model delete model_test").stdout).to match /SUCCESS/
            end

            it "should be visible in the database" do
                expect(command("mysql -u root --host 127.0.0.1 --database forseti_security --execute \"select count(*) from model where name = 'model_test';\"").stdout).to match /0/
            end

            it "should be visible in the database" do
                expect(command("mysql -u root --host 127.0.0.1 --database forseti_security --execute \"select count(*) from model where name = 'model_new';\"").stdout).to match /1/
            end

            after(:context) do
                command("forseti inventory purge 0").result
                command("forseti model delete model_new").result
            end
        end
    end
end

