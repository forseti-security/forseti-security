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
