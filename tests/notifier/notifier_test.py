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
"""Tests the notifier module."""

from datetime import datetime
import mock

from google.cloud.forseti.notifier import notifier
from tests.unittest_utils import ForsetiTestCase

FAKE_NOTIFIER_CONFIGS = {
    'resources': [
        {'notifiers': [
            {'configuration': {
                'sendgrid_api_key': 'SG.HmvWMOd_QKm',
                'recipient': 'ab@cloud.cc',
                'sender': 'cd@ex.com'},
                 'name': 'email_violations'},
            {'configuration': {
                'gcs_path': 'gs://fs-violations/scanner_violations'},
                'name': 'gcs_violations'}],
         'should_notify': True,
         'resource': 'policy_violations'}]}

FAKE_GLOBAL_CONFIGS = {
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

FAKE_VIOLATIONS = {
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
         'rule_index': 1L,
         'rule_name': 'Allow only service accounts to have access',
         'violation_data': {
             'full_name': 'o/5/g/f/4/g/f/9/g/p/be-p1-196611/bucket/be-1-ext/',
             'member': 'user:altair@gcp.work',
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
         'resource_type': 'bucket',
         'rule_index': 1L,
         'rule_name': 'Allow only service accounts to have access',
         'violation_data': {
             'full_name': 'o/5/g/f/4/g/f/9/g/p/be-p1-196611/bucket/be-1-ext/',
             'member': 'user:altair@gcp.work',
             'role': 'roles/storage.admin'},
         'violation_hash': 'f93745f39163060ceee17385b4677b91746382',
         'violation_type': 'IAP_VIOLATION'}],
    'policy_violations': [
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
         'resource_type': 'bucket',
         'rule_index': 1L,
         'rule_name': 'Allow only service accounts to have access',
         'violation_data': {
             'full_name': 'o/5/g/f/4/g/f/9/g/p/be-p1-196611/bucket/be-1-ext/',
             'member': 'user:altair@gcp.work',
             'role': 'roles/storage.objectAdmin'},
             'violation_hash': '15fda93a6fdd32d867064677cf07686f79b',
             'violation_type': 'ADDED'},
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
         'rule_index': 1L,
         'rule_name': 'Allow only service accounts to have access',
         'violation_data': {
             'full_name': 'o/5/g/f/4/g/f/9/g/p/be-p1-196611/bucket/be-1-ext/',
             'member': 'user:altair@gcp.work',
             'role': 'roles/storage.admin'},
             'violation_hash': 'f93745f39163060ceee17385b4677b91746',
             'violation_type': 'ADDED'}]}

class NotifierTest(ForsetiTestCase):
    def setUp(self):
        pass

    def test_can_convert_created_at_datetime_to_timestamp_string(self):
        violations = [
            mock.MagicMock(
                created_at_datetime=datetime(1999, 12, 25, 1, 2, 3)),
            mock.MagicMock(
                created_at_datetime=datetime(2010, 6, 8, 4, 5, 6))
        ]

        expected_timestamps = ['1999-12-25T01:02:03Z',
                               '2010-06-08T04:05:06Z']

        violations_with_converted_timestamp = (
            notifier.convert_to_timestamp(violations))

        converted_timestamps = []
        for i in violations_with_converted_timestamp:
            converted_timestamps.append(i.created_at_datetime)

        self.assertEquals(expected_timestamps,
                          converted_timestamps)

    @mock.patch(
        'google.cloud.forseti.notifier.notifier.find_notifiers', autospec=True)
    @mock.patch(
        'google.cloud.forseti.notifier.notifier.scanner_dao', autospec=True)
    def test_no_notifications_for_empty_violations(
        self, mock_dao, mock_find_notifiers):
        """No notifiers are instantiated/run if there are no violations.

        Setup:
            Mock the scanner_dao and make its map_by_resource() function return
            an empty violations map

        Expected outcome:
            The local find_notifiers() function is never called -> no notifiers
            are looked up, istantiated or run."""
        mock_dao.map_by_resource.return_value = dict()
        mock_srvc_cfg = mock.MagicMock()
        mock_srvc_cfg.get_global_config.return_value = FAKE_GLOBAL_CONFIGS
        mock_srvc_cfg.get_notifier_config.return_value = FAKE_NOTIFIER_CONFIGS
        notifier.run('iid-1-2-3', mock.MagicMock(), mock_srvc_cfg)
        self.assertFalse(mock_find_notifiers.called)

    @mock.patch(
        'google.cloud.forseti.notifier.notifier.find_notifiers', autospec=True)
    @mock.patch(
        'google.cloud.forseti.notifier.notifier.scanner_dao', autospec=True)
    def test_notifications_for_nonempty_violations(
        self, mock_dao, mock_find_notifiers):
        """The email/GCS upload notifiers are instantiated/run.

        Setup:
            Mock the scanner_dao and make its map_by_resource() function return
            the FAKE_VIOLATIONS dict

        Expected outcome:
            The local find_notifiers() is called with with 'email_violations'
            and 'gcs_violations' respectively. These 2 notifiers are
            instantiated and run."""
        mock_dao.map_by_resource.return_value = FAKE_VIOLATIONS
        mock_srvc_cfg = mock.MagicMock()
        mock_srvc_cfg.get_global_config.return_value = FAKE_GLOBAL_CONFIGS
        mock_srvc_cfg.get_notifier_config.return_value = FAKE_NOTIFIER_CONFIGS
        notifier.run('iid-1-2-3', mock.MagicMock(), mock_srvc_cfg)
        self.assertFalse(mock_find_notifiers.called)
