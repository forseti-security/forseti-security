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
"""Lien data to be used in the unit tests."""

from google.cloud.forseti.common.gcp_type import lien
from google.cloud.forseti.common.gcp_type import organization
from google.cloud.forseti.common.gcp_type import project
from google.cloud.forseti.common.gcp_type import resource
from google.cloud.forseti.scanner.audit import lien_rules_engine


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

_LIEN_JSON = """{
    "name": "liens/l1",
    "parent": "projects/p1",
    "restrictions": ["resourcemanager.projects.delete"],
    "origin": "testing",
    "createTime": "2018-09-05T14:45:46.534Z"
}
"""

LIEN = lien.Lien.from_json(PROJECT, _LIEN_JSON)

VIOLATIONS = [lien_rules_engine.RuleViolation(
    resource_id='p1',
    resource_name='Project with lien',
    resource_type=resource.ResourceType.PROJECT,
    full_name='organization/234/project/p1/',
    rule_index=0,
    rule_name='Lien test rule',
    violation_type='LIEN_VIOLATION',
    resource_data='',
)]
