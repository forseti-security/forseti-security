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

kms_resources_names = attribute('kms_resources_names')

require 'json'
control 'inventory' do

    describe "Inventory" do
        before :context do
            command("forseti inventory purge 0").result
            command("forseti inventory create").result

             # This variable cannot be used after all the inventories have been purged.
            @inventory_id = JSON.parse(command("forseti inventory list").stdout).fetch("id")
        end

        describe "Create an inventory" do

            it "should be visible from the command-line" do
                expect(command("forseti inventory list").stdout).to match /SUCCESS/
            end

            it "should be visible in the database" do
                expect(command("mysql -u root --host 127.0.0.1 --database forseti_security --execute \"select COUNT(DISTINCT gcp_inventory.inventory_index_id) from gcp_inventory join inventory_index ON inventory_index.id = gcp_inventory.inventory_index_id;\"").stdout).to match /1/
            end

             it "should be visible in the database" do
                 expect(command("mysql -u root --host 127.0.0.1 --database forseti_security --execute \"SELECT count(DISTINCT resource_data->>'$.lifecycleState') FROM gcp_inventory WHERE category = 'resource' and resource_type = 'project' and resource_data->>'$.lifecycleState' = 'ACTIVE';\"").stdout).to match /1/
             end

             it "should be visible in the database" do
                 expect(command("mysql -u root --host 127.0.0.1 --database forseti_security --execute \"SELECT count(DISTINCT resource_type) from gcp_inventory where resource_type in ('kms_cryptokey', 'kms_keyring');\"").stdout).to match /#{kms_resources_names.count}/
             end
        end

        describe "List an inventory" do

            it "should be visible from the command-line" do
                expect(command("forseti inventory list").stdout).to match /#{@inventory_id}/
            end

            it "should be visible in the database" do
                expect(command("mysql -u root --host 127.0.0.1 --database forseti_security --execute \"select count(DISTINCT gcp_inventory.inventory_index_id) from gcp_inventory join inventory_index on inventory_index.id = gcp_inventory.inventory_index_id where inventory_index.id = #{@inventory_id};\"").stdout).to match /1/
            end
        end

        describe "Get an inventory" do

            it "should be visible from the command-line" do
                expect(command("forseti inventory get #{@inventory_id}").stdout).to match /#{@inventory_id}/
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
                expect(command("forseti inventory delete #{@inventory_id}").stdout).to match /#{@inventory_id}/
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

            # Displays number of inventories in the database after purging inventories.
            it "should be visible in the database" do
                expect(command("mysql -u root --host 127.0.0.1 --database forseti_security --execute \"select count(*) from inventory_index;\"").stdout).to match /0/
            end
        end
    end
end

