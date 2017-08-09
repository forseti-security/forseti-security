# Copyright 2017 Google Inc.
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

"""Map of the APIs needed by the inventory pipelines."""

API_MAP = {
    'admin_api':
        {
            'module_name': 'admin_directory',
            'class_name': 'AdminDirectoryClient',
            'version': None
        },
    'appengine_api':
        {
            'module_name': 'appengine',
            'class_name': 'AppEngineClient',
            'version': None
        },
    'bigquery_api':
        {
            'module_name': 'bigquery',
            'class_name': 'BigQueryClient',
            'version': None
        },
    'cloudsql_api':
        {
            'module_name': 'cloudsql',
            'class_name': 'CloudsqlClient',
            'version': None
        },
    'compute_api':
        {
            'module_name': 'compute',
            'class_name': 'ComputeClient',
            'version': None
        },
    'compute_beta_api':
        {
            'module_name': 'compute',
            'class_name': 'ComputeClient',
            'version': 'beta'
        },
    'crm_api':
        {
            'module_name': 'cloud_resource_manager',
            'class_name': 'CloudResourceManagerClient',
            'version': None
        },
    'crm_v2beta1_api':
        {
            'module_name': 'cloud_resource_manager',
            'class_name': 'CloudResourceManagerClient',
            'version': 'v2beta1'
        },
    'gcs_api':
        {
            'module_name': 'storage',
            'class_name': 'StorageClient',
            'version': None
        },
    'iam_api':
        {
            'module_name': 'iam',
            'class_name': 'IAMClient',
            'version': None
        },
}
