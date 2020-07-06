# Copyright 2020 The Forseti Security Authors. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
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
firewall_name = attribute('firewall-allow-all-ingress-name')
model_name = SecureRandom.uuid.gsub!('-', '')[0..10]

control 'scanner-firewall-scanner' do
  # Arrange
  @inventory_id = /\"id\"\: \"([0-9]*)\"/.match(command("forseti inventory create --import_as #{model_name}").stdout)[1]
  describe command("forseti model use #{model_name}") do
    its('exit_status') { should eq 0 }
  end

  # Act
  describe command("forseti scanner run") do
    its('exit_status') { should eq 0 }
    its('stdout') { should match(/Scanner Index ID: (.*[0-9].*) is created/) }
  end

  # Assert Firewall violation found
  describe command("mysql -u #{db_user_name} -p#{db_password} --host 127.0.0.1 --execute \"SELECT COUNT(*) FROM forseti_security.violations V JOIN forseti_security.scanner_index SI ON SI.id = V.scanner_index_id WHERE SI.inventory_index_id = #{@inventory_id} AND V.violation_type = 'FIREWALL_BLACKLIST_VIOLATION' AND V.resource_name = '#{firewall_name}' AND V.rule_name = 'prevent_allow_all_ingress';\"") do
    its('exit_status') { should eq 0 }
    its('stdout') { should match(/1/) }
  end
end
