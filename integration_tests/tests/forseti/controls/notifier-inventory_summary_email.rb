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

email_sender = attribute('forseti_email_sender')
forseti_tests_path = "/home/ubuntu/forseti-security/integration_tests/tests/forseti"
kms_key = attribute('kms-key')
kms_keyring = attribute('kms-keyring')
model_name = SecureRandom.uuid.gsub!('-', '')[0..10]
pickle_plaintext="#{forseti_tests_path}/scripts/gmail_token.pickle"
pickle_ciphertext="#{forseti_tests_path}/scripts/gmail_token.pickle.enc"

control "notifier-inventory-summary-email" do
  # Install python requirements
  describe command("sudo pip3 install -r #{forseti_tests_path}/requirements.txt") do
    its('exit_status') { should eq 0 }
  end

  # Enable notifier inventory summary email
  describe command("sudo python3 #{forseti_tests_path}/scripts/update_server_config.py set_inventory_summary_email_enabled true") do
    its('exit_status') { should eq 0 }
  end

  # Decrypt token
  describe command("sudo gcloud kms decrypt --ciphertext-file=#{pickle_ciphertext} --plaintext-file=#{pickle_plaintext} --key=#{kms_key} --keyring=#{kms_keyring} --location=global") do
    its('exit_status') { should eq 0 }
  end

  # Create inventory/model
  @inventory_id = /\"id\"\: \"([0-9]*)\"/.match(command("forseti inventory create --import_as #{model_name}").stdout)[1]

  # Run notifier
  describe command("forseti notifier run") do
    its('exit_status') { should eq 0 }
    its('stdout') { should match(/Notification completed!/) }
  end

  # Verify the email is received
  describe command("python3 integration_tests/tests/forseti/verify_email.py --pickle_path #{pickle_plaintext} --sender #{email_sender}  --subject \"Inventory Summary: #{@inventory_id}\"") do
    its('exit_status') { should be > 0 }
  end

  # Delete plaintext token
  describe command ("sudo rm -rf #{pickle_plaintext}") do
    its('exit_status') { should eq 0 }
  end

  # Disable notifier inventory summary email
    describe command("sudo python3 #{forseti_tests_path}/scripts/update_server_config.py set_inventory_summary_email_enabled false") do
    its('exit_status') { should eq 0 }
  end

  # Delete the inventory
  describe command("forseti inventory delete #{@inventory_id}") do
    its('exit_status') { should eq 0 }
  end

  # Delete the model
  describe command("forseti model delete #{model_name}") do
    its('exit_status') { should eq 0 }
  end
end
