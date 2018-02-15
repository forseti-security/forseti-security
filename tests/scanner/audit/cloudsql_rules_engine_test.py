# Copyright 2017 The Forseti Security Authors. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Tests the CloudSqlRulesEngine."""

import json
import unittest
import mock
import yaml

from tests.unittest_utils import ForsetiTestCase
from google.cloud.forseti.common.gcp_type import cloudsql_access_controls
from google.cloud.forseti.common.util import file_loader
from google.cloud.forseti.scanner.audit.errors import InvalidRulesSchemaError
from google.cloud.forseti.scanner.audit import cloudsql_rules_engine as cre
from tests.unittest_utils import get_datafile_path


# TODO: Define more tests
class CloudSqlRulesEngineTest(ForsetiTestCase):
    """Tests for the CloudSqlRulesEngine."""

    def setUp(self):
        """Set up."""
        self.rule_index = 0
        self.cre = cre
        self.cre.LOGGER = mock.MagicMock()

    def test_build_rule_book_from_local_yaml_file_works(self):
        """Test that a RuleBook is built correctly with a yaml file."""
        rules_local_path = get_datafile_path(__file__,
            'cloudsql_test_rules_1.yaml')
        rules_engine = cre.CloudSqlRulesEngine(rules_file_path=rules_local_path)
        rules_engine.build_rule_book()
        self.assertEqual(2, len(rules_engine.rule_book.resource_rules_map))

    @mock.patch.object(file_loader,
                       '_read_file_from_gcs', autospec=True)
    def test_build_rule_book_from_gcs_works(self, mock_load_rules_from_gcs):
        """Test that a RuleBook is built correctly with a mocked gcs file.

        Setup:
            * Create a mocked GCS object from a test yaml file.
            * Get the yaml file content.

        Expected results:
            There are 4 resources that have rules, in the rule book.
        """
        bucket_name = 'bucket-name'
        rules_path = 'input/cloudsql_test_rules_1.yaml'
        full_rules_path = 'gs://{}/{}'.format(bucket_name, rules_path)
        rules_engine = cre.CloudSqlRulesEngine(rules_file_path=full_rules_path)

        # Read in the rules file
        file_content = None
        with open(get_datafile_path(__file__, 'cloudsql_test_rules_1.yaml'),
                  'r') as rules_local_file:
            try:
                file_content = yaml.safe_load(rules_local_file)
            except yaml.YAMLError:
                raise

        mock_load_rules_from_gcs.return_value = file_content

        rules_engine.build_rule_book()
        self.assertEqual(2, len(rules_engine.rule_book.resource_rules_map))

    def test_build_rule_book_no_resource_type_fails(self):
        """Test that a rule without a resource cannot be created."""
        rules_local_path = get_datafile_path(__file__,
            'cloudsql_test_rules_2.yaml')
        rules_engine = cre.CloudSqlRulesEngine(rules_file_path=rules_local_path)
        with self.assertRaises(InvalidRulesSchemaError):
            rules_engine.build_rule_book()

    def test_find_violation_for_publicly_exposed_acls(self):
        """Verify rules find violations."""
        rules_local_path = get_datafile_path(__file__,
                                             'cloudsql_test_rules_1.yaml')
        rules_engine = cre.CloudSqlRulesEngine(rules_file_path=rules_local_path)
        rules_engine.build_rule_book()
        rules_map = rules_engine.rule_book.resource_rules_map
        all_internet_no_ssl = rules_map[0]
        all_internet_ssl = rules_map[1]

        instance_dict = json.loads(SQL_INSTANCE_JSON)

        # No authorized networks
        acl = cloudsql_access_controls.CloudSqlAccessControl.from_json(
            'test-project', 'fake_full_name', SQL_INSTANCE_JSON)
        violation = all_internet_no_ssl.find_policy_violations(acl)
        self.assertEquals(0, len(list(violation)))
        violation = all_internet_ssl.find_policy_violations(acl)
        self.assertEquals(0, len(list(violation)))

        # Exposed to everyone in the world, no ssl
        network = json.loads(AUTHORIZED_NETWORK_TEMPLATE.format(
            value='0.0.0.0/0'))

        ip_configuration = instance_dict['settings']['ipConfiguration']
        ip_configuration['authorizedNetworks'].append(network)

        acl = cloudsql_access_controls.CloudSqlAccessControl.from_json(
            'test-project', 'fake_full_name', json.dumps(instance_dict))
        violation = all_internet_no_ssl.find_policy_violations(acl)
        self.assertEquals(1, len(list(violation)))
        violation = all_internet_ssl.find_policy_violations(acl)
        self.assertEquals(0, len(list(violation)))

        # Exposed to everyone in the world, ssl required.
        ip_configuration['requireSsl'] = True
        acl = cloudsql_access_controls.CloudSqlAccessControl.from_json(
            'test-project', 'fake_full_name', json.dumps(instance_dict))
        violation = all_internet_no_ssl.find_policy_violations(acl)
        self.assertEquals(0, len(list(violation)))
        violation = all_internet_ssl.find_policy_violations(acl)
        self.assertEquals(1, len(list(violation)))


SQL_INSTANCE_JSON = """
{
 "kind": "sql#instance",
 "name": "test-instance",
 "connectionName": "test-project:us-west1:test-instance",
 "project": "test-project",
 "state": "RUNNABLE",
 "backendType": "SECOND_GEN",
 "databaseVersion": "MYSQL_5_7",
 "region": "us-west1",
 "settings": {
  "kind": "sql#settings",
  "settingsVersion": "13",
  "authorizedGaeApplications": [
  ],
  "tier": "db-n1-standard-1",
  "backupConfiguration": {
   "kind": "sql#backupConfiguration",
   "startTime": "09:00",
   "enabled": true,
   "binaryLogEnabled": true
  },
  "pricingPlan": "PER_USE",
  "replicationType": "SYNCHRONOUS",
  "activationPolicy": "ALWAYS",
  "ipConfiguration": {
   "ipv4Enabled": true,
   "authorizedNetworks": [
   ]
  },
  "locationPreference": {
   "kind": "sql#locationPreference",
   "zone": "us-west1-a"
  },
  "dataDiskSizeGb": "10",
  "dataDiskType": "PD_SSD",
  "maintenanceWindow": {
   "kind": "sql#maintenanceWindow",
   "hour": 0,
   "day": 0
  },
  "storageAutoResize": true,
  "storageAutoResizeLimit": "0"
 },
 "serverCaCert": {
  "kind": "sql#sslCert",
  "instance": "test-instance",
  "sha1Fingerprint": "1234567890",
  "commonName": "C=US,O=Test",
  "certSerialNumber": "0",
  "cert": "-----BEGIN CERTIFICATE----------END CERTIFICATE-----",
  "createTime": "2017-11-22T17:59:22.085Z",
  "expirationTime": "2019-11-22T18:00:22.085Z"
 },
 "ipAddresses": [
  {
   "ipAddress": "10.0.0.1",
   "type": "PRIMARY"
  }
 ],
 "instanceType": "CLOUD_SQL_INSTANCE",
 "gceZone": "us-west1-a"
}
"""

AUTHORIZED_NETWORK_TEMPLATE = """
{{
 "kind": "sql#aclEntry",
 "name": "",
 "value": "{value}"
}}
"""


if __name__ == '__main__':
    unittest.main()
