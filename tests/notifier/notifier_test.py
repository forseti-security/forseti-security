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
import unittest

from google.cloud.forseti.notifier import notifier
from google.cloud.forseti.notifier.notifiers import email_violations
from google.cloud.forseti.notifier.notifiers import gcs_violations
from tests.notifier.notifiers.test_data import fake_violations
from tests.unittest_utils import ForsetiTestCase


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
        mock_service_cfg = mock.MagicMock()
        mock_service_cfg.get_global_config.return_value = fake_violations.GLOBAL_CONFIGS
        mock_service_cfg.get_notifier_config.return_value = fake_violations.NOTIFIER_CONFIGS
        notifier.run('iid-1-2-3', mock.MagicMock(), mock_service_cfg)
        self.assertFalse(mock_find_notifiers.called)

    @mock.patch(
        ('google.cloud.forseti.notifier.notifiers.email_violations'
         '.EmailViolations'), autospec=True)
    @mock.patch(
        'google.cloud.forseti.notifier.notifiers.gcs_violations.GcsViolations',
        autospec=True)
    @mock.patch(
        'google.cloud.forseti.notifier.notifier.find_notifiers', autospec=True)
    @mock.patch(
        'google.cloud.forseti.notifier.notifier.scanner_dao', autospec=True)
    def test_notifications_for_nonempty_violations(
        self, mock_dao, mock_find_notifiers, mock_gcs_violations_cls, mock_email_violations_cls):
        """The email/GCS upload notifiers are instantiated/run.

        Setup:
            Mock the scanner_dao and make its map_by_resource() function return
            the VIOLATIONS dict

        Expected outcome:
            The local find_notifiers() is called with with 'email_violations'
            and 'gcs_violations' respectively. These 2 notifiers are
            instantiated and run."""
        mock_dao.map_by_resource.return_value = fake_violations.VIOLATIONS
        mock_service_cfg = mock.MagicMock()
        mock_service_cfg.get_global_config.return_value = fake_violations.GLOBAL_CONFIGS
        mock_service_cfg.get_notifier_config.return_value = fake_violations.NOTIFIER_CONFIGS

        mock_email_violations = mock.MagicMock(spec=email_violations.EmailViolations)
        mock_email_violations_cls.return_value = mock_email_violations
        mock_gcs_violations = mock.MagicMock(spec=gcs_violations.GcsViolations)
        mock_gcs_violations_cls.return_value = mock_gcs_violations
        mock_find_notifiers.side_effect = [mock_email_violations_cls, mock_gcs_violations_cls]
        notifier.run('iid-1-2-3', mock.MagicMock(), mock_service_cfg)

        # The notifiers were only run once i.e. for 'policy_violations'
        self.assertTrue(mock_find_notifiers.called)
        self.assertEquals(1, mock_email_violations_cls.call_count)
        self.assertEquals(
            'policy_violations',
            mock_email_violations_cls.call_args[0][0])
        self.assertEquals(1, mock_email_violations.run.call_count)

        self.assertEquals(1, mock_gcs_violations_cls.call_count)
        self.assertEquals(
            'policy_violations',
            mock_gcs_violations_cls.call_args[0][0])
        self.assertEquals(1, mock_gcs_violations.run.call_count)


class InventorySummaryNotifierTest(ForsetiTestCase):
    """Tests for the inventory summary notifier."""

    def setUp(self):
        """Setup."""
        ForsetiTestCase.setUp(self)
        self.fake_utcnow = datetime(year=1920, month=5, day=6, hour=7, minute=8)

    def tearDown(self):
        """Tear down method."""
        ForsetiTestCase.tearDown(self)

    @mock.patch(
        'google.cloud.forseti.notifier.notifier.run_inv_summary',
        autospec=True)
    @mock.patch(
        'google.cloud.forseti.notifier.notifier.find_notifiers', autospec=True)
    @mock.patch(
        'google.cloud.forseti.notifier.notifier.scanner_dao', autospec=True)
    def test_inventory_summary_is_called(
        self, mock_dao, mock_find_notifiers, mock_inv_summary):
        """No violation notifiers are run if there are no violations.
        Setup:
            Mock the scanner_dao and make its map_by_resource() function return
            an empty violations map
        Expected outcome:
            The local find_notifiers() function is never called -> no notifiers
            are looked up, istantiated or run.
            The `run_inv_summary` function *is* called.
            """
        mock_dao.map_by_resource.return_value = dict()
        mock_service_cfg = mock.MagicMock()
        mock_service_cfg.get_global_config.return_value = fake_violations.GLOBAL_CONFIGS
        mock_service_cfg.get_notifier_config.return_value = fake_violations.NOTIFIER_CONFIGS
        notifier.run('iid-1-2-3', mock.MagicMock(), mock_service_cfg)
        self.assertFalse(mock_find_notifiers.called)
        self.assertTrue(mock_inv_summary.called)

    @mock.patch('google.cloud.forseti.notifier.notifier.LOGGER', autospec=True)
    def test_no_inventory_in_config(self, mock_logger):
        mock_service_config = mock.MagicMock()
        mock_service_config.get_notifier_config.return_value = dict()
        notifier.run_inv_summary('blah', mock_service_config)
        self.assertTrue(mock_logger.info.called)
        self.assertEquals(
            'No "inventory" configuration for notifier.',
            mock_logger.info.call_args[0][0])

    @mock.patch('google.cloud.forseti.notifier.notifier.LOGGER', autospec=True)
    def test_no_inventory_summary_in_config(self, mock_logger):
        mock_service_config = mock.MagicMock()
        mock_service_config.get_notifier_config.return_value = dict(
            inventory=dict(blah=1))
        notifier.run_inv_summary('blah', mock_service_config)
        self.assertTrue(mock_logger.info.called)
        self.assertEquals(
            'No "inventory summary" configuration for notifier.',
            mock_logger.info.call_args[0][0])

    @mock.patch('google.cloud.forseti.notifier.notifier.LOGGER', autospec=True)
    def test_inventory_summary_not_enabled_in_config(self, mock_logger):
        mock_service_config = mock.MagicMock()
        mock_service_config.get_notifier_config.return_value = dict(
            inventory=dict(summary=dict(enabled=False)))
        notifier.run_inv_summary('blah', mock_service_config)
        self.assertTrue(mock_logger.info.called)
        self.assertEquals(
            'Inventory summary notifications are turned off.',
            mock_logger.info.call_args[0][0])

    @mock.patch('google.cloud.forseti.notifier.notifier.LOGGER', autospec=True)
    def test_inventory_summary_gcs_path_not_set_in_config(self, mock_logger):
        mock_service_config = mock.MagicMock()
        mock_service_config.get_notifier_config.return_value = dict(
            inventory=dict(summary=dict(enabled=True)))
        notifier.run_inv_summary('blah', mock_service_config)
        self.assertTrue(mock_logger.error.called)
        self.assertEquals(
            '"gcs_path" not set for inventory summary notifier.',
            mock_logger.error.call_args[0][0])

    @mock.patch('google.cloud.forseti.notifier.notifier.LOGGER', autospec=True)
    def test_inventory_summary_invalid_gcs_path(self, mock_logger):
        mock_service_config = mock.MagicMock()
        mock_service_config.get_notifier_config.return_value = dict(
            inventory=dict(summary=dict(enabled=True, gcs_path='invalid')))
        notifier.run_inv_summary('blah', mock_service_config)
        self.assertTrue(mock_logger.error.called)
        self.assertEquals(
            'Invalid GCS path: %s', mock_logger.error.call_args[0][0])
        self.assertEquals('invalid', mock_logger.error.call_args[0][1])

    @mock.patch('google.cloud.forseti.notifier.notifier.LOGGER', autospec=True)
    def test_inventory_summary_no_summary_data(self, mock_logger):
        mock_inv_index = mock.MagicMock()
        mock_inv_index.get_summary.return_value = dict()

        mock_session = mock.MagicMock()
        mock_session.query.return_value.get.return_value = mock_inv_index

        mock_service_config = mock.MagicMock()
        mock_service_config.scoped_session.return_value.__enter__.return_value = mock_session
        mock_service_config.get_notifier_config.return_value = dict(
            inventory=dict(summary=dict(enabled=True, gcs_path='gs://xx')))

        notifier.run_inv_summary('blah', mock_service_config)
        self.assertTrue(mock_logger.warn.called)
        self.assertEquals(
            'No inventory summary data found.',
            mock_logger.warn.call_args[0][0])

    @mock.patch(
        'google.cloud.forseti.notifier.notifier.InventorySummary',
        autospec=True)
    def test_inv_summary_can_run_successfully(self, mock_inventory_summary):
        mock_inv_index = mock.MagicMock()
        mock_inv_index.get_summary.return_value = {
            'bucket': 2, 'object': 1, 'organization': 1, 'project': 2}

        mock_session = mock.MagicMock()
        mock_session.query.return_value.get.return_value = mock_inv_index

        mock_service_config = mock.MagicMock()
        mock_service_config.scoped_session.return_value.__enter__.return_value = mock_session
        mock_service_config.get_notifier_config.return_value = dict(
            inventory=dict(summary=dict(enabled=True, gcs_path='gs://xx')))

        notifier.run_inv_summary('blah', mock_service_config)
        self.assertTrue(mock_inventory_summary.called)
        self.assertEquals('blah', mock_inventory_summary.call_args[0][0])
        expected_inv_summary = [
            {'count': 2, 'resource_type': 'project'},
            {'count': 1, 'resource_type': 'organization'},
            {'count': 1, 'resource_type': 'object'},
            {'count': 2, 'resource_type': 'bucket'}]
        self.assertEquals(
            expected_inv_summary, mock_inventory_summary.call_args[0][1])
        self.assertEquals(
            dict(enabled=True, gcs_path='gs://xx'),
            mock_inventory_summary.call_args[0][2])
        self.assertTrue(mock_inventory_summary.return_value.run.called)


if __name__ == '__main__':
    unittest.main()
