# Copyright 2018 The Forseti Security Authors. All rights reserved.
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

"""Test data for Cloud Security Command Center GCP api responses."""

ORGANIZATION_ID = 'organizations/88888'
FAKE_ALPHA_FINDING = """
{
    "assetIds": ["full_name_111"],
    "category": "UNKNOWN_RISK",
    "eventTime": "2010-08-28T10:20:30Z",
    "id": "f3eb2be2ed015563d7dc4d4aea798a0b269b76ea590a7672b43113428d48da943f2f5a1b44ad7850aa266add296cc548df88a12a30ba307519af9b314e6eaef8",
        "properties": {
            "inventory_index_id": "iii",
            "resource_data": "inventory_data_111",
            "resource_id": "fake_firewall_111",
            "resource_type": "firewall_rule",
            "rule_index": 111,
            "scanner_index_id": 1282990830000000,
            "violation_data": {"policy_names": ["fw-tag-match_111"], "recommended_actions": {"DELETE_FIREWALL_RULES": ["fw-tag-match_111"]}}},
            "source_id": "FORSETI"
}
"""

EXPECTED_CREATE_FINDING_RESULT = """
    {'expected_result': 'foo'}
"""

PERMISSION_DENIED = """
{
 "error": {
  "code": 403,
  "message": "The caller does not have permission",
  "status": "PERMISSION_DENIED"
 }
}
"""