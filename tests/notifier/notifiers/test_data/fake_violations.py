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
"""Fake violation data."""

NOTIFIER_CONFIGS = {
    'email_connector': {
        'name': 'sendgrid',
        'auth': {
            'api_key': 'SG.O9'
        },
        'sender': 'forseti-notify@mycompany',
        'recipient': 'john@john.com',
        'data_format': 'csv'
    },
    'resources': [
        {'resource': 'iam_policy_violations',
         'notifiers': [
             {'name': 'email_violations',
              'configuration': {
                  'sendgrid_api_key': 'SG.HmvWMOd_QKm',
                  'recipient': 'ab@cloud.cc',
                  'sender': 'cd@ex.com'}},
             {'name': 'gcs_violations',
              'configuration': {
                  'gcs_path': 'gs://fs-violations/scanner_violations'}}],
         'should_notify': True}]}

NOTIFIER_CONFIGS_GCS_JSON = {
    'resources': [
        {'notifiers': [
            {'configuration': {
                'gcs_path': 'gs://fs-violations/scanner_violations',
                'data_format': 'json'},
             'name': 'gcs_violations'}],
         'should_notify': True,
         'resource': 'iam_policy_violations'}]}

NOTIFIER_CONFIGS_GCS_DEFAULT = {
    'resources': [
        {'notifiers': [
            {'configuration': {
                'gcs_path': 'gs://fs-violations/scanner_violations'},
             'name': 'gcs_violations'}],
         'should_notify': True,
         'resource': 'iam_policy_violations'}]}

NOTIFIER_CONFIGS_GCS_INVALID_DATA_FORMAT = {
    'resources': [
        {'notifiers': [
            {'configuration': {
                'gcs_path': 'gs://fs-violations/scanner_violations',
                'data_format': 'xxx-invalid'},
             'name': 'gcs_violations'}],
         'should_notify': True,
         'resource': 'iam_policy_violations'}]}

NOTIFIER_CONFIGS_EMAIL_JSON = {
    'email_connector': {
        'name': 'sendgrid',
        'auth': {
            'api_key': 'SG.O9'
        },
        'sender': 'forseti-notify@mycompany',
        'recipient': 'john@john.com',
        'data_format': 'json'
    },
    'resources': [
        {'notifiers': [
            {'name': 'email_violations'}],
         'should_notify': True,
         'resource': 'iam_policy_violations'}]}

NOTIFIER_CONFIGS_EMAIL_DEFAULT = {
    'email_connector': {
        'name': 'sendgrid',
        'auth': {
            'api_key': 'SG.O9'
        },
        'sender': 'forseti-notify@mycompany',
        'recipient': 'john@john.com',
        'data_format': 'csv'
    },
    'resources': [
        {'notifiers': [
            {'name': 'email_violations'}],
         'should_notify': True,
         'resource': 'iam_policy_violations'}]}

NOTIFIER_CONFIGS_EMAIL_INVALID_DATA_FORMAT = {
    'email_connector': {
        'name': 'sendgrid',
        'auth': {
            'api_key': 'SG.O9'
        },
        'sender': 'forseti-notify@mycompany',
        'recipient': 'john@john.com',
        'data_format': 'xyz-invalid'
    },
    'resources': [
        {'notifiers': [
            {'name': 'email_violations'}],
         'should_notify': True,
         'resource': 'iam_policy_violations'}]}

GLOBAL_CONFIGS = {
    'max_bigquery_api_calls_per_100_seconds': 17000,
    'max_cloudbilling_api_calls_per_60_seconds': 300,
    'max_compute_api_calls_per_second': 20,
    'max_results_admin_api': 500,
    'max_sqladmin_api_calls_per_100_seconds': 100,
    'max_container_api_calls_per_100_seconds': 1000,
    'max_crm_api_calls_per_100_seconds': 400,
    'domain_super_admin_email': 'chsl@vkvd.com',
    'db_name': 'forseti-inventory',
    'db_user': 'forseti_user',
    'max_admin_api_calls_per_100_seconds': 1500,
    'db_host': '127.0.0.1',
    'groups_service_account_key_file': '/tmp/forseti-gsuite-reader.json',
    'max_appengine_api_calls_per_second': 20,
    'max_iam_api_calls_per_second': 20}

VIOLATIONS = {
    'iap_violations': [
        {'created_at_datetime': '2018-03-16T09:29:52Z',
         'full_name': 'o/5/g/f/4/g/f/9/g/p/be-p1-196611/bucket/be-1-ext/',
         'id': 47L,
         'inventory_data': {
             'bindings': [
                 {'members': ['pEditor:be-p1-196611', 'pOwner:be-p1-196611'],
                  'role': 'roles/storage.legacyBucketOwner'},
                 {'members': ['pViewer:be-p1-196611'],
                  'role': 'roles/storage.legacyBucketReader'}],
             'etag': 'CAE=',
             'kind': 'storage#policy',
             'resourceId': 'ps/_/buckets/be-1-ext'},
         'inventory_index_id': '2018-03-14T14:49:36.101287',
         'resource_id': 'be-1-ext',
         'resource_type': 'bucket',
         'resource_name': 'be-1-ext',
         'rule_index': 1L,
         'rule_name': 'Allow only service accounts to have access',
         'violation_data': {
             'full_name': 'o/5/g/f/4/g/f/9/g/p/be-p1-196611/bucket/be-1-ext/',
             'member': 'user:abc@example.com',
             'role': 'roles/storage.objectAdmin'},
         'violation_hash': '15fda93a6fdd32d867064677cf07686f79b65d',
         'violation_type': 'IAP_VIOLATION'},
        {'created_at_datetime': '2018-03-16T09:29:52Z',
         'full_name': 'o/5/g/f/4/g/f/9/g/p/be-p1-196611/bucket/be-1-ext/',
         'id': 48L,
         'inventory_data': {
             'bindings': [
                 {'members': ['pEditor:be-p1-196611', 'pOwner:be-p1-196611'],
                  'role': 'roles/storage.legacyBucketOwner'},
                 {'members': ['pViewer:be-p1-196611'],
                  'role': 'roles/storage.legacyBucketReader'}],
             'etag': 'CAE=',
             'kind': 'storage#policy',
             'resourceId': 'ps/_/buckets/be-1-ext'},
         'inventory_index_id': '2018-03-14T14:49:36.101287',
         'resource_id': 'be-1-ext',
         'resource_name': 'be-1-ext',
         'resource_type': 'bucket',
         'rule_index': 1L,
         'rule_name': 'Allow only service accounts to have access',
         'violation_data': {
             'full_name': 'o/5/g/f/4/g/f/9/g/p/be-p1-196611/bucket/be-1-ext/',
             'member': 'user:def@example.com',
             'role': 'roles/storage.admin'},
         'violation_hash': 'f93745f39163060ceee17385b4677b91746382',
         'violation_type': 'IAP_VIOLATION'}],
    'iam_policy_violations': [
        {'created_at_datetime': '2018-03-16T09:29:52Z',
         'full_name': 'o/5/g/f/4/g/f/9/g/p/be-p1-196611/bucket/be-1-ext/',
         'id': 1L,
         'inventory_data': {
             'bindings': [
                 {'members': ['pEditor:be-p1-196611', 'pOwner:be-p1-196611'],
                  'role': 'roles/storage.legacyBucketOwner'},
                 {'members': ['pViewer:be-p1-196611'],
                  'role': 'roles/storage.legacyBucketReader'}],
             'etag': 'CAE=',
             'kind': 'storage#policy',
             'resourceId': 'ps/_/buckets/be-1-ext'},
         'inventory_index_id': '2018-03-14T14:49:36.101287',
         'resource_id': 'be-1-ext',
         'resource_name': 'be-1-ext',
         'resource_type': 'bucket',
         'rule_index': 1L,
         'rule_name': 'Allow only service accounts to have access',
         'violation_data': {
             'full_name': 'o/5/g/f/4/g/f/9/g/p/be-p1-196611/bucket/be-1-ext/',
             'member': 'user:ghi@example.com',
             'role': 'roles/storage.objectAdmin'},
         'violation_hash': '15fda93a6fdd32d867064677cf07686f79b',
         'violation_type': 'IAM_POLICY_VIOLATION'},
        {'created_at_datetime': '2018-03-16T09:29:52Z',
         'full_name': 'o/5/g/f/4/g/f/9/g/p/be-p1-196611/bucket/be-1-ext/',
         'id': 2L,
         'inventory_data': {
             'bindings': [
                 {'members': ['pEditor:be-p1-196611', 'pOwner:be-p1-196611'],
                  'role': 'roles/storage.legacyBucketOwner'},
                 {'members': ['pViewer:be-p1-196611'],
                  'role': 'roles/storage.legacyBucketReader'}],
             'etag': 'CAE=',
             'kind': 'storage#policy',
             'resourceId': 'ps/_/buckets/be-1-ext'},
         'inventory_index_id': '2018-03-14T14:49:36.101287',
         'resource_id': 'be-1-ext',
         'resource_type': 'bucket',
         'resource_name': 'be-1-ext',
         'rule_index': 1L,
         'rule_name': 'Allow only service accounts to have access',
         'violation_data': {
             'full_name': 'o/5/g/f/4/g/f/9/g/p/be-p1-196611/bucket/be-1-ext/',
             'member': 'user:jkl@example.com',
             'role': 'roles/storage.admin'},
         'violation_hash': 'f93745f39163060ceee17385b4677b91746',
         'violation_type': 'IAM_POLICY_VIOLATION'}]}
