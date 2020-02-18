# Copyright 2020 The Forseti Security Authors. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the 'License');
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an 'AS IS' BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Test violation data."""

CONFIG_VALIDATOR_VIOLATIONS = [
    {
        'id': 1,
        'created_at_datetime': '2020-02-05T09:29:52Z',
        'full_name': 'organization/123/project/test-project/bucket/test-bucket/',
        'resource_data': '{}',
        'resource_name': '//storage.googleapis.com/test-bucket',
        'resource_id': 'test-bucket',
        'resource_type': 'storage.googleapis.com/Bucket',
        'rule_index': 0,
        'rule_name': 'always_violates_all',
        'scanner_index_id': 1,
        'violation_data': '{"asset": {"ancestry_path": "organization/123/project/test-project/", "asset_type": "storage.googleapis.com/Bucket", "name": "//storage.googleapis.com/test-bucket", "resource": {"data": {}, "version": "v1"}}, "constraint": {"kind": "GCPAlwaysViolatesConstraintV1", "name": "always_violates_all"}}',
        'violation_hash': '15fda93a6fdd32d867064677cf07686f79b',
        'violation_message': 'always_violates_all violates on all resources.',
        'violation_type': 'CV_always_violates_all'
    },
    {
        'id': 2,
        'created_at_datetime': '2020-02-05T09:29:52Z',
        'full_name': 'organization/123/project/test-project/cloudsqlinstance/456/',
        'resource_data': '{}',
        'resource_name': '//cloudsql.googleapis.com/projects/test-project/instances/test-db',
        'resource_id': 'test-db',
        'resource_type': 'sqladmin.googleapis.com/Instance',
        'rule_index': 0,
        'rule_name': 'allow_some_sql_location',
        'scanner_index_id': 1,
        'violation_data': '{"location": "us-central1", "resource": "//cloudsql.googleapis.com/projects/test-project/instances/test-db"}',
        'violation_hash': '7745b8e9c82ebd6297d6d733067dc23907c481feb674cd730d50e01a9c9d795dda8cba899d35620b03a396e3f3bd0796a90744812fd5b6586044bd0a8050a45e',
        'violation_message': '//cloudsql.googleapis.com/projects/test-project/instances/test-db is in a disallowed location (us-central1).',
        'violation_type': 'CV_allow_some_sql_location'
    }
]
