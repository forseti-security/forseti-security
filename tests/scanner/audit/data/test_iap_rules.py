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

"""Rules to use in IAP rules engine unit tests."""

# Default rule, don't allow alternate services or direct access.
RULES1 = {
    'rules': [{
            'name': 'my rule',
            'resource': [{
                    'type': 'organization',
                    'applies_to': 'self_and_children',
                    'resource_ids': ['778899']
                }, {
                    'type': 'project',
                    'applies_to': 'self',
                    'resource_ids': [
                        'my-project-1',
                        'my-project-2',
                    ]
                }],
            'inherit_from_parents': False,
        }]
}

RULES2 = {
    'rules': [
        {
            'name': 'my rule',
            'resource': [{
                    'type': 'organization',
                    'applies_to': 'self_and_children',
                    'resource_ids': ['778899']
                }, {
                    'type': 'project',
                    'applies_to': 'self',
                    'resource_ids': [
                        'my-project-1',
                        'my-project-2',
                    ]
                }],
            'inherit_from_parents': False,
            'allowed_alternate_services': ['other-service'],
            'allowed_direct_access_sources': ['10.0.0.0/8'],
            'allowed_iap_enabled': 'True',
        }, {
            'name': 'my other rule',
            'resource': [{
                    'type': 'project',
                    'applies_to': 'self',
                    'resource_ids': ['my-project-2',]
                }],
            'allowed_direct_access_sources': ['web-monitoring'],
        },
    ]
}
