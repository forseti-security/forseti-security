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
                expect(command("forseti model list").stderr).to eq ""
            end

            it "should be visible from the command-line" do
                expect(command("forseti model list").stdout).to match /model_new/
            end
        end

        describe "Use a model" do

            it "should be visible from the command-line" do
                expect(command("forseti model use model_new").stderr).to eq ""
            end

            it "should be visible from the command-line" do
                expect(command("forseti model use model_new").stdout).to eq ""
            end

            it "should be visible from the command-line" do
                expect(command("forseti config show").stdout).to match /model/
            end
        end

        describe "Delete a model" do

            before :context do
                command("forseti model create --inventory_index_id #{@inventory_id} model_test").result
                command("forseti model use model_test").result
            end

            it "should be visible from the command-line" do
                expect(command("forseti model list").stdout).to match /model_test/
            end

            it "should be visible from the command-line" do
                expect(command("forseti model delete model_new").stdout).to match /SUCCESS/
            end

            it "should be visible in the database" do
                expect(command("mysql -u root --host 127.0.0.1 --database forseti_security --execute \"select count(*) from model where name = 'model_test';\"").stdout).to match /1/
            end

            it "should be visible in the database" do
                expect(command("mysql -u root --host 127.0.0.1 --database forseti_security --execute \"select count(*) from model where name = 'model_new';\"").stdout).to match /0/
            end

            after(:context) do
                command("forseti inventory purge 0").result
                command("forseti model delete model_new").result
            end
        end
    end
end

