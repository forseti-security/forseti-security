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
    'appengine': {
        'version': 'v1'
    },
    'bigquery': {
        'version': 'v2'
    },
    'cloudresourcemanager': {
        'version': 'v1'
    },
    'compute': {
        'version': 'v1'
    },
    'storage': {
        'version': 'v1'
    },
    'admin': {
        'version': 'directory_v1'
    },
    'sqladmin': {
        'version': 'v1beta4'
    },
    'iam': {
        'version': 'v1'
    },
}
