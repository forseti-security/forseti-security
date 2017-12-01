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

"""Tests BaseNotificationPipeline."""

import mock
import tempfile
import unittest

from datetime import datetime

import MySQLdb

from google.cloud.forseti.notifier.pipelines import base_notification_pipeline as bnp
from tests.unittest_utils import ForsetiTestCase

class FakePipeline(bnp.BaseNotificationPipeline):
    def run():
        pass


class BaseNotificationPipelineTest(ForsetiTestCase):
    """Tests for base_notification_pipeline."""

    @mock.patch(
        'google.cloud.forseti.common.data_access._db_connector.DbConnector',
        autospec=True)
    def setUp(self, mock_conn):
        """Setup."""
        fake_global_conf = {
            'db_host': 'x',
            'db_name': 'y',
            'db_user': 'z',
        }
        fake_pipeline_conf = {
            'gcs_path': 'gs://blah'
        }

        self.fake_pipeline = FakePipeline(
            'abc', '123', None, fake_global_conf, {}, fake_pipeline_conf)

    @mock.patch(
        'google.cloud.forseti.common.data_access.violation_dao.ViolationDao',
        autospec=True)
    def test_get_violation_dao(self, mock_violation_dao):
        """Test _get_violation_dao()."""
        self.fake_pipeline._get_violation_dao()
        mock_violation_dao.assert_called_once_with(self.fake_pipeline.global_configs)

    @mock.patch.object(bnp.BaseNotificationPipeline, '_get_violation_dao')
    def test_get_violations(self, mock_violation_dao):
        """Test _get_violations()."""
        fake_timestamp = '1111'

        got_violations = ['a', 'b', 'c']
        got_bucket_acl_violations = ['x', 'y', 'z']

        mock_get_all_violations = mock.MagicMock(
            side_effect=[got_violations, got_bucket_acl_violations])

        mock_violation_dao.return_value.get_all_violations = mock_get_all_violations

        expected = {
            'violations': got_violations,
            'bucket_acl_violations': got_bucket_acl_violations
        }
        actual = self.fake_pipeline._get_violations(fake_timestamp)
        self.assertEquals(expected, actual)


if __name__ == '__main__':
    unittest.main()

