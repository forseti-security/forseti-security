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

"""Forwarding Rules Rule Scanner Test"""

from builtins import object
import unittest.mock as mock

from tests.unittest_utils import ForsetiTestCase
from google.cloud.forseti.scanner.scanners import forwarding_rule_scanner
from tests.unittest_utils import get_datafile_path
from google.cloud.forseti.common.gcp_type import forwarding_rule as fr


class ForwardingRule(object):
    """Represents ForwardRule resource."""

class ForwardingRuleScannerTest(ForsetiTestCase):

    def test_forwarding_rules_scanner_all_match(self):
        rules_local_path = get_datafile_path(__file__,
            'forward_rule_test_1.yaml')
        scanner = forwarding_rule_scanner.ForwardingRuleScanner(
            {}, {}, mock.MagicMock(), '', '', rules_local_path)

        project_id = "abc-123"

        gcp_forwarding_rules_resource_data = [
            {
                "id": "46",
                "creationTimestamp": "2017-06-01 04:19:37",
                "name": "abc-123",
                "description": "",
                "region": "https://www.googleapis.com/compute/v1/projects/abc-123/regions/asia-east1",
                "IPAddress": "198.51.100.99",
                "IPProtocol": "UDP",
                "portRange": "4500-4500",
                "ports": [],
                "target": "https://www.googleapis.com/compute/v1/projects/abc-123/regions/asia-east1/abc-123/abc-123",
                "loadBalancingScheme": "EXTERNAL",
            },
            {
                "id": "23",
                "creationTimestamp": "2017-06-01 04:19:37",
                "name": "abc-123",
                "description": "",
                "region": "https://www.googleapis.com/compute/v1/projects/abc-123/regions/asia-east1",
                "IPAddress": "198.51.100.23",
                "IPProtocol": "TCP",
                "ports": [8080],
                "target": "https://www.googleapis.com/compute/v1/projects/abc-123/regions/asia-east1/abc-123/abc-123",
                "loadBalancingScheme": "INTERNAL",
            },
            {
                "id": "46",
                "creationTimestamp": "2017-06-01 04:19:37",
                "name": "abc-123",
                "description": "",
                "region": "https://www.googleapis.com/compute/v1/projects/abc-123/regions/asia-east1",
                "IPAddress": "198.51.100.46",
                "IPProtocol":  "ESP",
                "ports": [],
                "target": "https://www.googleapis.com/compute/v1/projects/abc-123/regions/asia-east1/abc-123/abc-123",
                "loadBalancingScheme":  "EXTERNAL",
            },
            {
                "id": "46",
                "creationTimestamp": "2017-06-01 04:19:37",
                "name": "abc-123",
                "description": "",
                "region": "https://www.googleapis.com/compute/v1/projects/abc-123/regions/asia-east1",
                "IPAddress": "198.51.100.35",
                "IPProtocol":  "TCP",
                "portRange": "4500-4500",
                "target": "https://www.googleapis.com/compute/v1/projects/abc-123/regions/asia-east1/abc-123/abc-123",
                "loadBalancingScheme":  "EXTERNAL",
            }
        ]
        gcp_forwarding_rules_resource_objs = []
        for gcp_forwarding_rule_resource_data in gcp_forwarding_rules_resource_data:
            gcp_forwarding_rules_resource_objs.append(
                fr.ForwardingRule.from_dict(
                    project_id, '', gcp_forwarding_rule_resource_data))

        violations = scanner._find_violations(gcp_forwarding_rules_resource_objs)
        self.assertEqual(0, len(violations))

    def test_forwarding_rules_scanner_no_match(self):
        rules_local_path = get_datafile_path(__file__,
            'forward_rule_test_1.yaml')
        scanner = forwarding_rule_scanner.ForwardingRuleScanner(
            {}, {}, mock.MagicMock(), '', '', rules_local_path)

        project_id = "abc-123"
        
        gcp_forwarding_rules_resource_data = [
            {
                "id": "46",
                "creationTimestamp": "2017-06-01 04:19:37",
                "name": "abc-123",
                "description": "",
                "region": "https://www.googleapis.com/compute/v1/projects/abc-123/regions/asia-east1",
                "IPAddress": "198.51.100.99",
                "IPProtocol": "TCP",
                "portRange": "4500-4500",
                "ports": [],
                "target": "https://www.googleapis.com/compute/v1/projects/abc-123/regions/asia-east1/abc-123/abc-123",
                "loadBalancingScheme": "EXTERNAL",
            },
            {
                "id": "23",
                "creationTimestamp": "2017-06-01 04:19:37",
                "name": "abc-123",
                "description": "",
                "region": "https://www.googleapis.com/compute/v1/projects/abc-123/regions/asia-east1",
                "IPAddress": "198.51.100.23",
                "IPProtocol": "TCP",
                "ports": [8081],
                "target": "https://www.googleapis.com/compute/v1/projects/abc-123/regions/asia-east1/abc-123/abc-123",
                "loadBalancingScheme": "INTERNAL",
            },
            {
                "id": "46",
                "creationTimestamp": "2017-06-01 04:19:37",
                "name": "abc-123",
                "description": "",
                "region": "https://www.googleapis.com/compute/v1/projects/abc-123/regions/asia-east1",
                "IPAddress": "198.51.101.46",
                "IPProtocol":  "ESP",
                "ports": [],
                "target": "https://www.googleapis.com/compute/v1/projects/abc-123/regions/asia-east1/abc-123/abc-123",
                "loadBalancingScheme":  "EXTERNAL",
            },
            {
                "id": "46",
                "creationTimestamp": "2017-06-01 04:19:37",
                "name": "abc-123",
                "description": "",
                "region": "https://www.googleapis.com/compute/v1/projects/abc-123/regions/asia-east1",
                "IPAddress": "198.51.100.35",
                "IPProtocol":  "TCP",
                "portRange": "4400-4500",
                "target": "https://www.googleapis.com/compute/v1/projects/abc-123/regions/asia-east1/abc-123/abc-123",
                "loadBalancingScheme":  "EXTERNAL",
            }
        ]
        gcp_forwarding_rules_resource_objs = []
        for gcp_forwarding_rule_resource_data in gcp_forwarding_rules_resource_data:
            gcp_forwarding_rules_resource_objs.append(
                fr.ForwardingRule.from_dict(
                    project_id, '', gcp_forwarding_rule_resource_data)
                )

        violations = scanner._find_violations(gcp_forwarding_rules_resource_objs)
        self.assertEqual(4, len(violations))


if __name__ == '__main__':
    unittest.main()
