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

"""Test data for the Auditor, as a module (for importability)."""

import collections
import os
import yaml


TEST_RULES_PATH = os.path.abspath(os.path.dirname(__file__))


def _load_yaml(filename):
    with open(os.path.join(TEST_RULES_PATH, filename)) as fp:
        return yaml.safe_load(fp)


VALID_RULES1 = _load_yaml('test_valid_rules1.yaml')

INVALID_RULES1 = _load_yaml('test_invalid_rules1.yaml')
INVALID_RULES1_DUP_IDS = [
    rule_id
    for rule_id, count in collections.Counter(
        [r['id'] for r in INVALID_RULES1['rules']]).items() if count > 1]

FAKE_RULES_CONFIG1 = {
    'rules': [
        {
            'type': 'google.cloud.security.auditor.rules.rule.Rule',
            'id': 'rules.fake.1',
            'description': 'Fake rule',
            'configuration': {
                'variables': [
                    'xyz'
                ],
                'resources': [
                    {
                        'type': 'google.cloud.security.common.gcp_type.project.Project',
                        'variables': {'xyz': 'project_id'}
                    }
                ],
                'condition': [
                    '1 == 1'
                ]
            }
        },
        {
            'type': 'google.cloud.security.auditor.rules.rule.Rule',
            'id': 'rules.fake.2',
            'description': 'Fake rule 2',
            'configuration': {
                'variables': [
                    'abc'
                ],
                'resources': [
                    {
                        'type': 'google.cloud.security.common.gcp_type.organization.Organization',
                        'variables': {'abc': 'organization_id'}
                    }
                ],
                'condition': [
                    '1 == 1'
                ]
            }
        }
    ]
}

FAKE_INVALID_RULES_CONFIG1 = {
    'rules': [
        {
            'type': 'google.cloud.security.auditor.rules.rule.NonexistentRule',
            'id': 'rules.fake.1',
            'description': 'Fake rule',
            'configuration': {
                'variables': [
                    'xyz'
                ],
                'resources': [
                    {
                        'type': 'google.cloud.security.common.gcp_type.project.Project',
                        'variables': {'xyz': 'project_id'}
                    }
                ],
                'condition': [
                    '1 == 1'
                ]
            }
        },
    ]
}
