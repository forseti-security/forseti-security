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
control 'Scanner' do


   describe "Run scanner" do

       before :context do
           command("forseti inventory purge 0").result
           command("forseti inventory create").result
           @inventory_id = JSON.parse(command("forseti inventory list").stdout).fetch("id")
           command("forseti model create --inventory_index_id #{@inventory_id} model_scanner").result
           command("forseti model use model_scanner").result
           command("sudo cp /home/ubuntu/forseti-security/configs/forseti_conf_server.yaml /home/ubuntu/forseti-security/configs/forseti_conf_server_backup.yaml").result
           @modified_yaml = yaml('/home/ubuntu/forseti-security/configs/forseti_conf_server.yaml').params
           @modified_yaml["scanner"]["scanners"][0]["enabled"] = "true"
           command("echo -en \"#{@modified_yaml.to_yaml}\" | sudo tee /home/ubuntu/forseti-security/configs/forseti_conf_server.yaml").result
           command("forseti server configuration reload").result
       end

           it "should be visible from the command-line" do
               expect(command("forseti scanner run").stdout).to match /AuditLoggingScanner/
           end

           it "should be visible from the command-line" do
               expect(command("forseti scanner run").stdout).to match /Scan completed/
           end

       after :context do
           command("sudo mv /home/ubuntu/forseti-security/configs/forseti_conf_server_backup.yaml /home/ubuntu/forseti-security/configs/forseti_conf_server.yaml").result
           command("forseti server configuration reload").result
           command("forseti inventory purge 0").result
           command("forseti model delete model_scanner").result
       end
   end
end

