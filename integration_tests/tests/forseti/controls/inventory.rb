require 'json'
control 'inventory' do

    describe "Inventory" do
        before :context do
            command("forseti inventory purge 0").result
            command("forseti inventory create").result
            command("sudo apt-get -y install mysql-client").result

             # This variable cannot be used after all the inventories have been purged..
            @inventory_id = JSON.parse(command("forseti inventory list").stdout).fetch("id")
        end

        describe "Create an inventory" do

            it "should be visible from the command-line" do
                expect(command("forseti inventory list").stdout).to match /SUCCESS/
            end

            it "should be visible in the database" do
                expect(command("mysql -u root --host 127.0.0.1 --database forseti_security --execute \"select COUNT(DISTINCT gcp_inventory.inventory_index_id) from gcp_inventory join inventory_index ON inventory_index.id = gcp_inventory.inventory_index_id;\"").stdout).to match /1/
            end

             # The count is higher as there are a lot of projects in pending delete state.
             it "should be visible in the database" do
                 expect(command("mysql -u root --host 127.0.0.1 --database forseti_security --execute \"select count(DISTINCT resource_id) from gcp_inventory where category='resource' and resource_type = 'project';\"").stdout).to match /68/
             end
        end

        describe "List an inventory" do

            it "should be visible from the command-line" do
                expect(command("forseti inventory list").stderr).to eq ""
            end

            it "should be visible in the database" do
                expect(command("mysql -u root --host 127.0.0.1 --database forseti_security --execute \"select count(DISTINCT gcp_inventory.inventory_index_id) from gcp_inventory join inventory_index on inventory_index.id = gcp_inventory.inventory_index_id where inventory_index.id = #{@inventory_id};\"").stdout).to match /1/
            end
        end

        describe "Get an inventory" do

            it "should be visible from the command-line" do
                expect(command("forseti inventory get #{@inventory_id}").stderr).to eq ""
            end

            it "should be visible in the database" do
                expect(command("mysql -u root --host 127.0.0.1 --database forseti_security --execute \"select * from inventory_index where id = #{@inventory_id};\"").stdout).to match /1/
            end
        end

        describe "Delete an inventory" do

            before :context do
                command("forseti inventory create").result
            end

            # Displays number of inventories in the database before purging inventories.
            it "should be visible in the database" do
                expect(command("mysql -u root --host 127.0.0.1 --database forseti_security --execute \"select count(DISTINCT gcp_inventory.inventory_index_id) from gcp_inventory join inventory_index ON inventory_index.id = gcp_inventory.inventory_index_id;\"").stdout).to match /2/
            end

            it "should be visible from the command-line" do
                expect(command("forseti inventory delete #{@inventory_id}").stderr).to match ""
            end

            # Displays number of inventories in the database after deleting an inventory.
            it "should be visible in the database" do
                expect(command("mysql -u root --host 127.0.0.1 --database forseti_security --execute \"select count(DISTINCT gcp_inventory.inventory_index_id) from gcp_inventory join inventory_index ON inventory_index.id = gcp_inventory.inventory_index_id;\"").stdout).to match /1/
            end
        end

        describe "Purge an inventory" do

            before :context do
                command("forseti inventory create").result
            end

            # Displays number of inventories in the database before purging.
            it "should be visible in the database" do
                expect(command("mysql -u root --host 127.0.0.1 --database forseti_security --execute \"select count(DISTINCT gcp_inventory.inventory_index_id) from gcp_inventory join inventory_index ON inventory_index.id = gcp_inventory.inventory_index_id;\"").stdout).to match /2/
            end

            it "should be visible from the command-line" do
                expect(command("forseti inventory purge 0").stdout).to match /purged/
            end

            # Displays number of inventories in the database after purging inventories.
            it "should be visible in the database" do
                expect(command("mysql -u root --host 127.0.0.1 --database forseti_security --execute \"select count(DISTINCT gcp_inventory.inventory_index_id) from gcp_inventory join inventory_index ON inventory_index.id = gcp_inventory.inventory_index_id;\"").stdout).to match /0/
            end
        end
    end
end

