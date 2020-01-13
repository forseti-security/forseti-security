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

firewall_rule_name = attribute('enforcer_allow_all_icmp_rule_name')
project_id = attribute('project_id')

control "enforcer-remediates-firewall-rule" do
  # Get the latest firewall rules
  fw_rules_cmd = command("sudo gcloud compute firewall-rules list --format=json")
  describe fw_rules_cmd do
    its('exit_status') { should eq 0 }
  end

  fw_rules = JSON.parse(fw_rules_cmd.stdout)
  filtered_rules = []
  fw_rules.each { |rule|
    if  /#{firewall_rule_name}/.match(rule["name"])
      # mark all rules generated for this test for deletion
      next
    end

    # Remove all the attributes enforcer does not like
    rule.delete("kind")
    rule.delete("selfLink")
    rule.delete("id")
    rule.delete("creationTimestamp")
    rule.delete("targetServiceAccounts")
    rule.delete("sourceServiceAccounts")
    filtered_rules.push(rule)
  }

  # Write the current firewall rules to a json file
  describe command("echo '#{JSON.dump(filtered_rules)}' > /tmp/current_fw_rule.json") do
    its('exit_status') { should eq 0 }
  end

  # Make sure the file exist
  describe file('/tmp/current_fw_rule.json') do
    it { should exist }
  end

  # Act
  describe command("forseti_enforcer --enforce_project #{project_id} --policy_file /tmp/current_fw_rule.json") do
    its('exit_status') { should eq 0 }
  end

  # Assert
  describe command("sudo gcloud compute firewall-rules list --format=json") do
    its('exit_status') { should eq 0 }
    its('stdout') { should_not match(/#{Regexp.quote(firewall_rule_name)}/) }
  end

  # Cleanup
  describe command("rm /tmp/current_fw_rule.json") do
    its('exit_status') { should eq 0 }
  end
  describe file('/tmp/current_fw_rule.json') do
    it { should_not exist }
  end
end
