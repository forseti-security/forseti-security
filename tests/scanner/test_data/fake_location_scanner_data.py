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
"""Location data to be used in the unit tests."""

from google.cloud.forseti.common.gcp_type import bucket
from google.cloud.forseti.common.gcp_type import organization
from google.cloud.forseti.common.gcp_type import project
from google.cloud.forseti.scanner.audit import location_rules_engine


ORGANIZATION = organization.Organization(
    '234',
    display_name='Organization 234',
    full_name='organization/234/',
    data='fake_org_data_234',
)

PROJECT = project.Project(
    'p1',
    project_number=11223344,
    display_name='Project with lien',
    parent=ORGANIZATION,
    full_name='organization/234/project/p1/',
    data='fake_project_data_2341',
)

_BUCKET_JSON = """{
    "id": "p1-b1",
    "parent": "projects/p1",
    "location": "EUROPE-WEST1"
}
"""

BUCKET = bucket.Bucket.from_json(PROJECT, _BUCKET_JSON)

def build_violations(res):
    return [location_rules_engine.RuleViolation(
        resource_id=res.id,
        resource_name=res.display_name,
        resource_type=res.type,
        full_name=res.full_name,
        rule_index=0,
        rule_name='Location test rule',
        violation_type='LOCATION_VIOLATION',
        violation_data=str(res.locations),
        resource_data=res.data,
    )]
