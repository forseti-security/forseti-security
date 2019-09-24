require 'json'
control 'model' do

    describe "Model" do
        before :context do
            command("forseti inventory purge 0").result
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

        describe "List a model" do

            it "should be visible from the command-line" do
                expect(command("forseti model list model_new").stderr).to eq ""
            end
        end

        describe "Use a model" do

            it "should be visible from the command-line" do
                expect(command("forseti model use model_new").stderr).to eq ""
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
end
