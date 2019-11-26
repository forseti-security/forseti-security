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

require 'securerandom'
require 'json'

forseti_server_vm_name = attribute('forseti-server-vm-name')
project_id = attribute('project_id')
random_string = SecureRandom.uuid.gsub!('-', '')[0..10]

control "logs-debug-level" do

  # Get the instance id
  instance_describe_cmd = command("gcloud compute instances describe #{forseti_server_vm_name} --zone us-central1-c --format=json")
  describe instance_describe_cmd do
    its('exit_status') { should eq 0 }
  end
  instance_id = JSON.parse(instance_describe_cmd.stdout)["id"]

  # Set the log level to debug
  describe command("forseti server log_level set debug") do
    its('exit_status') { should eq 0 }
    its('stdout') { should match /isSuccess": true/}
  end

  # Note the timestamp
  timestamp = Time.now.getutc.strftime('%Y-%m-%dT%H:%M:%S.%3NZ')

  # Create inventory
  inventory_cmd = command("forseti inventory create --import_as #{random_string}")
  describe inventory_cmd do
    its('exit_status') { should eq 0 }
  end
  @inventory_id = /\"id\"\: \"([0-9]*)\"/.match(inventory_cmd.stdout)[1]

  describe command("sleep 60") do
    its('exit_status') { should eq 0 }
  end
  # sleep(60)

  # Get all debug logs for the instance after the noted timestamp
  gcloud_log_read_cmd = command("gcloud logging read 'resource.type=gce_instance AND resource.labels.instance_id=#{instance_id} AND logName=projects/#{project_id}/logs/forseti AND severity=DEBUG AND timestamp>=\"#{timestamp}\"' --limit=10 | grep -c \"severity: DEBUG\"")

  describe gcloud_log_read_cmd do
    its('stdout') { should match /10/ }
  end

  # reset log level
  describe command("forseti server log_level set info") do
    its('exit_status') { should eq 0 }
  end

  describe command("forseti inventory delete #{@inventory_id}") do
    its('exit_status') { should eq 0 }
  end
end
