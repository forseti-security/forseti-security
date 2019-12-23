# Copyright 2019 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

require 'json'
require 'yaml'
require 'securerandom'

cai_dump_file_gcs_paths = attribute('inventory-performance-cai-dump-paths')
db_password = attribute('forseti-cloudsql-password')
db_user_name = attribute('forseti-cloudsql-user')
model_name = SecureRandom.uuid.gsub!('-', '')[0..10]

conf_path = "/home/ubuntu/forseti-security/configs/forseti_conf_server.yaml"

control "inventory-performance" do
  # Arrange
  # Update forseti config: disable api polling, fake org id, gcs paths
  # Make backup of server config
  describe command("cp #{conf_path} /tmp/forseti_conf_server_backup.yaml") do
    its('exit_status') { should eq 0 }
  end

  @modified_yaml = yaml(conf_path).params
  # fake org id
  @modified_yaml["inventory"]["root_resource_id"] = "organizations/5456546415"
  # disable_polling: set to True for all found
  @modified_yaml["inventory"]["api_quota"].keys.each do |key|
    @modified_yaml["inventory"]["api_quota"][key]["disable_polling"] = true
  end
  # under cai: section: cai_dump_file_gcs_paths: ['gs://forseti-server-XXXXX/testing-iam-policy.dump','gs://forseti-server-XXXX/testing-resource.dump']
  # @modified_yaml["inventory"]["cai"]["cai_dump_file_gcs_paths"] = cai_dump_file_gcs_paths
  @modified_yaml["inventory"]["cai"]["cai_dump_file_gcs_paths"] = [
      "gs://forseti-test-data-orange/inventory_performance/mock_cai_iam_policy.dump",
      "gs://forseti-test-data-orange/inventory_performance/mock_cai_resource.dump"
  ]
  describe command("echo -en \"#{@modified_yaml.to_yaml}\" | sudo tee #{conf_path}") do
    its('exit_status') { should eq 0 }
  end
  describe command("forseti server configuration reload") do
    its('exit_status') { should eq 0 }
  end

  # Disable the cronjob
  describe command("sudo su - ubuntu -c 'crontab -l > /tmp/crontab_backup.txt'") do
    its('exit_status') { should eq 0 }
  end
  describe command("sudo su - ubuntu -c 'crontab -r'") do
    its('exit_status') { should eq 0 }
  end

  # Act
  @inventory_id = /\"id\"\: \"([0-9]*)\"/.match(command("forseti inventory create --import_as #{model_name}").stdout)[1]

  describe command("forseti inventory create --import_as #{model_name}") do
    its('exit_status') { should eq 0 }
  end

  # Assert
  # Assert Inventory takes less than 12 minutes
  # select * from inventory_index where id = @inventory_id
  # Compare completeTimestamp and startTimestamp, it should not be more than 12 mins apart
  describe command("mysql -u #{db_user_name} -p#{db_password} --host 127.0.0.1 --database forseti_security --execute \"SELECT COUNT(*) FROM inventory_index where id=#{@inventory_id}\"") do
    its('exit_status') { should eq 0 }
    its('stdout') { should match (/lets_see_what_it_says/)}
  end

  # Assert resource count
  # select count(*) from gcp_inventory where inventory_index_id=@inventory_id; ==== 296612
  describe command("mysql -u #{db_user_name} -p#{db_password} --host 127.0.0.1 --database forseti_security --execute \"SELECT COUNT(*) FROM gcp_inventory where inventory_index_id=#{@inventory_id}\"") do
    its('exit_status') { should eq 0 }
    its('stdout') { should match (/296612/)}
  end

  # Assert bigquery_table count == 250000
  # select count(*) from gcp_inventory where inventory_index_id=@inventory_id AND resource_type = 'bigquery_table' AND category = 'resource';
  describe command("mysql -u #{db_user_name} -p#{db_password} --host 127.0.0.1 --database forseti_security --execute \"SELECT COUNT(*) FROM gcp_inventory where inventory_index_id=#{@inventory_id} AND resource_type = 'bigquery_table' AND category = 'resource';\"") do
    its('exit_status') { should eq 0 }
    its('stdout') { should match (/250000/)}
  end

  # Assert project count == 1000
  # select count(*) from gcp_inventory where inventory_index_id=@inventory_id AND resource_type = 'project';
  describe command("mysql -u #{db_user_name} -p#{db_password} --host 127.0.0.1 --database forseti_security --execute \"SELECT COUNT(*) FROM gcp_inventory where inventory_index_id=#{@inventory_id} AND resource_type = 'project';\"") do
    its('exit_status') { should eq 0 }
    its('stdout') { should match (/1000/)}
  end

  # Restore server config backup
  describe command("sudo cp /tmp/forseti_conf_server_backup.yaml #{conf_path}") do
    its('exit_status') { should eq 0 }
  end
  describe command("forseti server configuration reload") do
    its('exit_status') { should eq 0 }
  end


  # Restore cron job
  describe command("sudo su - ubuntu -c 'crontab /tmp/crontab_backup.txt && crontab -l'") do
    its('exit_status') { should eq 0 }
  end

  # Cleanup
  describe command("forseti inventory delete #{@inventory_id}") do
    its('exit_status') { should eq 0 }
  end
end
