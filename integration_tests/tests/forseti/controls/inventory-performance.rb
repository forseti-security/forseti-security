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
require 'securerandom'

db_password = attribute('forseti-cloudsql-password')
db_user_name = attribute('forseti-cloudsql-user')

control "inventory-get-list" do
  # Arrange
  # Update forseti config: disable api polling, fake org id, gcs paths
  # Make backup of server config
  # disable_polling: set to True for all found
  # root_resource_id: organizations/5456546415
  # under cai: section: cai_dump_file_gcs_paths: ['gs://forseti-server-XXXXX/testing-iam-policy.dump','gs://forseti-server-XXXX/testing-resource.dump']

  # Disable the cronjob
  # sudo su ubuntu
  # crontab -l > my_cron_backup.txt
  # crontab -r

  # Act
  inventory_create = command("forseti inventory create")
  describe(inventory_create) do
    its('exit_status') { should eq 0 }
    its('stdout') { should match (/\"id\"\: \"([0-9]*)\"/)}
  end
  @inventory_id = /\"id\"\: \"([0-9]*)\"/.match(inventory_create.stdout)[1]


  # Assert
  # Assert Inventory takes less than 12 minutes
  # select * from invnetory_index where id = @inventory_id
  # Compare completeTimestamp and startTimestamp, it should not be more than 12 mins apart

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

  # Cleanup
  describe command("forseti inventory delete #{@inventory_id}") do
    its('exit_status') { should eq 0 }
  end

  # Restore server config backup
  
  # Restore cron job
  #crontab my_cron_backup.txt
end
