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
"""Resource data to be used in the unit tests."""

from google.cloud.forseti.common.gcp_type import resource_util
from google.cloud.forseti.scanner.audit import resource_rules_engine


_ORGANIZATION_JSON = """{
    "name": "organizations/234"
}
"""

ORGANIZATION = resource_util.create_resource_from_json(
    'organization', None, _ORGANIZATION_JSON)

_PROJECT1_JSON = """{
    "projectId": "p1",
    "name": "Project 1"
}
"""

PROJECT1 = resource_util.create_resource_from_json(
    'project', ORGANIZATION, _PROJECT1_JSON)

_PROJECT2_JSON = """{
    "projectId": "p2",
    "name": "Project 2"
}
"""

PROJECT2 = resource_util.create_resource_from_json(
    'project', ORGANIZATION, _PROJECT2_JSON)

_BUCKET_JSON = """{
    "id": "p1-bucket1",
    "parent": "projects/p1",
    "location": "EUROPE-WEST1"
}
"""

BUCKET = resource_util.create_resource_from_json(
    'bucket', PROJECT1, _BUCKET_JSON)

def build_violations(res):
    """Build an expected violation.

    Args:
        res (Resource): resource to create violation from.

    Returns:
        RuleViolation: The violation.
    """
    return [resource_rules_engine.RuleViolation(
        resource_id=res.id,
        resource_name=res.display_name,
        resource_type=res.type,
        full_name=res.full_name,
        rule_index=0,
        rule_name='Resource test rule',
        violation_type='RESOURCE_VIOLATION',
        resource_data=res.data or '',
        violation_data='',
    )]
