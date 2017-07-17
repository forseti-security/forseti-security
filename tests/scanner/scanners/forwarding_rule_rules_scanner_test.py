# Copyright 2017 Google Inc.
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

"""Forwarding Rules Rule Scanner Test"""

import mock

from tests.unittest_utils import ForsetiTestCase
from google.cloud.security.scanner.scanners import forwarding_rule_scanner
from google.cloud.security.scanner.audit import forwarding_rule_rules_engine as fre
from tests.unittest_utils import get_datafile_path
from google.cloud.security.common.gcp_type import forwarding_rule as fr


class ForwardingRule(object):
    """Represents ForwardRule resource."""

class ForwardingRuleScannerTest(ForsetiTestCase):

    def test_fowarding_rules_scanner_all_match(self):
        rules_local_path = get_datafile_path(__file__,
            'foward_rule_test_1.yaml')
        scanner = forwarding_rule_scanner.ForwardingRuleScanner({}, {}, '', rules_local_path)

        gcp_forwarding_rules_resource_data = [
            {
                "project_id": "abc-123",
                "resource_id": "46",
                "creation_timestamp": "2017-06-01 04:19:37",
                "name": "abc-123",
                "description": "",
                "region": "https://www.googleapis.com/compute/v1/projects/abc-123/regions/asia-east1",
                "ip_address": "198.51.100.99",
                "ip_protocol": "UDP",
                "port_range": "4500-4500",
                "ports": "[]",
                "target": "https://www.googleapis.com/compute/v1/projects/abc-123/regions/asia-east1/abc-123/abc-123",
                "load_balancing_scheme": "EXTERNAL",
            },
            {
                "project_id": "abc-123",
                "resource_id": "23",
                "creation_timestamp": "2017-06-01 04:19:37",
                "name": "abc-123",
                "description": "",
                "region": "https://www.googleapis.com/compute/v1/projects/abc-123/regions/asia-east1",
                "ip_address": "198.51.100.23",
                "ip_protocol": "TCP",
                "ports": "[8080]",
                "target": "https://www.googleapis.com/compute/v1/projects/abc-123/regions/asia-east1/abc-123/abc-123",
                "load_balancing_scheme": "INTERNAL",
            },
            {
                "project_id": "abc-123",
                "resource_id": "46",
                "creation_timestamp": "2017-06-01 04:19:37",
                "name": "abc-123",
                "description": "",
                "region": "https://www.googleapis.com/compute/v1/projects/abc-123/regions/asia-east1",
                "ip_address": "198.51.100.46",
                "ip_protocol":  "ESP",
                "ports": "[]",
                "target": "https://www.googleapis.com/compute/v1/projects/abc-123/regions/asia-east1/abc-123/abc-123",
                "load_balancing_scheme":  "EXTERNAL",
            },
            {
                "project_id": "abc-123",
                "resource_id": "46",
                "creation_timestamp": "2017-06-01 04:19:37",
                "name": "abc-123",
                "description": "",
                "region": "https://www.googleapis.com/compute/v1/projects/abc-123/regions/asia-east1",
                "ip_address": "198.51.100.35",
                "ip_protocol":  "TCP",
                "port_range": "4500-4500",
                "target": "https://www.googleapis.com/compute/v1/projects/abc-123/regions/asia-east1/abc-123/abc-123",
                "load_balancing_scheme":  "EXTERNAL",
            }
        ]
        gcp_forwarding_rules_resource_objs = []
        for gcp_forwarding_rule_resource_data in gcp_forwarding_rules_resource_data:
            gcp_forwarding_rules_resource_objs.append(
                    fr.ForwardingRule(**gcp_forwarding_rule_resource_data)
                )

        violations = scanner._find_violations(gcp_forwarding_rules_resource_objs)
        self.assertEqual(0, len(violations))

    def test_fowarding_rules_scanner_no_match(self):
        rules_local_path = get_datafile_path(__file__,
            'foward_rule_test_1.yaml')
        scanner = forwarding_rule_scanner.ForwardingRuleScanner({}, {}, '', rules_local_path)

        gcp_forwarding_rules_resource_data = [
            {
                "project_id": "abc-123",
                "resource_id": "46",
                "creation_timestamp": "2017-06-01 04:19:37",
                "name": "abc-123",
                "description": "",
                "region": "https://www.googleapis.com/compute/v1/projects/abc-123/regions/asia-east1",
                "ip_address": "198.51.100.99",
                "ip_protocol": "TCP",
                "port_range": "4500-4500",
                "ports": "[]",
                "target": "https://www.googleapis.com/compute/v1/projects/abc-123/regions/asia-east1/abc-123/abc-123",
                "load_balancing_scheme": "EXTERNAL",
            },
            {
                "project_id": "abc-123",
                "resource_id": "23",
                "creation_timestamp": "2017-06-01 04:19:37",
                "name": "abc-123",
                "description": "",
                "region": "https://www.googleapis.com/compute/v1/projects/abc-123/regions/asia-east1",
                "ip_address": "198.51.100.23",
                "ip_protocol": "TCP",
                "ports": "[8081]",
                "target": "https://www.googleapis.com/compute/v1/projects/abc-123/regions/asia-east1/abc-123/abc-123",
                "load_balancing_scheme": "INTERNAL",
            },
            {
                "project_id": "abc-123",
                "resource_id": "46",
                "creation_timestamp": "2017-06-01 04:19:37",
                "name": "abc-123",
                "description": "",
                "region": "https://www.googleapis.com/compute/v1/projects/abc-123/regions/asia-east1",
                "ip_address": "198.51.101.46",
                "ip_protocol":  "ESP",
                "ports": "[]",
                "target": "https://www.googleapis.com/compute/v1/projects/abc-123/regions/asia-east1/abc-123/abc-123",
                "load_balancing_scheme":  "EXTERNAL",
            },
            {
                "project_id": "abc-123",
                "resource_id": "46",
                "creation_timestamp": "2017-06-01 04:19:37",
                "name": "abc-123",
                "description": "",
                "region": "https://www.googleapis.com/compute/v1/projects/abc-123/regions/asia-east1",
                "ip_address": "198.51.100.35",
                "ip_protocol":  "TCP",
                "port_range": "4400-4500",
                "target": "https://www.googleapis.com/compute/v1/projects/abc-123/regions/asia-east1/abc-123/abc-123",
                "load_balancing_scheme":  "EXTERNAL",
            }
        ]
        gcp_forwarding_rules_resource_objs = []
        for gcp_forwarding_rule_resource_data in gcp_forwarding_rules_resource_data:
            gcp_forwarding_rules_resource_objs.append(
                    fr.ForwardingRule(**gcp_forwarding_rule_resource_data)
                )

        violations = scanner._find_violations(gcp_forwarding_rules_resource_objs)
        self.assertEqual(4, len(violations))

if __name__ == '__main__':
    unittest.main()
