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

"""The APIs supported by the discovery service.

Not intended to be an exhaustive list (which can be retrieved from
discovery.get()).
"""

SUPPORTED_APIS = {
    'admin': {
        'default_version': 'directory_v1',
        'supported_versions': ['directory_v1']
    },
    'appengine': {
        'default_version': 'v1',
        'supported_versions': ['v1']
    },
    'bigquery': {
        'default_version': 'v2',
        'supported_versions': ['v2']
    },
    'cloudasset': {
        'default_version': 'v1',
        'supported_versions': ['v1'],
    },
    'cloudbilling': {
        'default_version': 'v1',
        'supported_versions': ['v1']
    },
    'cloudresourcemanager': {
        'default_version': 'v1',
        'supported_versions': ['v1', 'v2']
    },
    'compute': {
        'default_version': 'v1',
        'supported_versions': ['v1', 'beta']
    },
    'container': {
        'default_version': 'v1',
        'supported_versions': ['v1', 'v1beta1']
    },
    'groupssettings': {
        'default_version': 'v1',
        'supported_versions': ['v1']
    },
    'iam': {
        'default_version': 'v1',
        'supported_versions': ['v1']
    },
    'logging': {
        'default_version': 'v2',
        'supported_versions': ['v2']
    },
    'securitycenter': {
        'default_version': 'v1alpha3',
        'supported_versions': ['v1alpha3'],
        'is_private_api': True,
    },
    'servicemanagement': {
        'default_version': 'v1',
        'supported_versions': ['v1']
    },
    'sqladmin': {
        'default_version': 'v1beta4',
        'supported_versions': ['v1beta4']
    },
    'storage': {
        'default_version': 'v1',
        'supported_versions': ['v1']
    }
}
