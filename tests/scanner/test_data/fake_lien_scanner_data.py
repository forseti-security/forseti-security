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

import json

from google.cloud.forseti.common.gcp_type import resource
from google.cloud.forseti.scanner.audit import lien_rules_engine


LIEN_DATA = [{
    'name': 'liens/l1',
    'parent': 'projects/p1',
    'full_name': 'organization/234/project/p1/lien/l1/',
    'restrictions': ['resourcemanager.projects.delete'],
}]

EXPECTED_LIEN_VIOLATIONS = [
    lien_rules_engine.RuleViolation(
        resource_id='l1',
        resource_type=resource.ResourceType.LIEN,
        full_name='organization/234/project/p1/lien/l1/',
        rule_index=0,
        rule_name='Lien test rule',
        violation_type='LIEN_VIOLATION',
        resource_data=json.dumps(LIEN_DATA[0]),
    ),
]
