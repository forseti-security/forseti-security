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

"""Tests the Dao."""

from google.apputils import basetest
import mock
import MySQLdb

from google.cloud.security.common.data_access import _db_connector
from google.cloud.security.common.data_access import errors
from google.cloud.security.common.data_access import violation_dao
from google.cloud.security.common.data_access import violation_map as vm
from google.cloud.security.common.data_access.sql_queries import load_data
from google.cloud.security.common.gcp_type import iam_policy as iam
from google.cloud.security.scanner.audit import rules


class ViolationDaoTest(basetest.TestCase):
    """Tests for the Dao."""

    @mock.patch.object(_db_connector.DbConnector, '__init__', autospec=True)
    def setUp(self, mock_db_connector):
        mock_db_connector.return_value = None
        self.resource_name = 'violations'
        self.dao = violation_dao.ViolationDao()
        self.fake_snapshot_timestamp = '12345'
        self.fake_table_name = ('%s_%s' %
            (self.resource_name, self.fake_snapshot_timestamp))
        self.fake_violations = [
            rules.RuleViolation(
                resource_type='x',
                resource_id='1',
                rule_name='rule name',
                rule_index=0,
                violation_type='ADDED',
                role='roles/editor',
                members=[iam.IamPolicyMember.create_from(m)
                    for m in ['user:a@foo.com', 'user:b@foo.com']],
            ),
            rules.RuleViolation(
                resource_type='%sb' % ('a'*300),
                resource_id='1',
                rule_name='%sd' % ('c'*300),
                rule_index=1,
                violation_type='REMOVED',
                role='%s' % ('e'*300),
                members=[iam.IamPolicyMember.create_from(
                    'user:%sh' % ('g'*300))],
            ),
        ]

        self.expected_fake_violations = [
            ('x', '1', 'rule name', 0, 'ADDED',
             'roles/editor', 'user:a@foo.com'),
            ('x', '1', 'rule name', 0, 'ADDED',
             'roles/editor', 'user:b@foo.com'),
            ('a'*255, '1', 'c'*255, 1, 'REMOVED',
             'e'*255, ('user:%s' % ('g'*300))[:255]),
        ]

    def test_format_violation(self):
        """Test that a RuleViolation is formatted and flattened properly.

        Setup:
            Create some rule violations:
              * With multiple members.
              * With really long text values for properties.

        Expect:
            _format_violation() will flatten the violation and truncate the
            property values accordingly.
        """

        resource_name = 'violations'
        actual = [f for v in self.fake_violations
                    for f in violation_dao._format_violation(v, resource_name)]

        self.assertEquals(self.expected_fake_violations, actual)

    def test_insert_violations_no_timestamp(self):
        """Test that insert_violations() is properly called.

        Setup:
            Create mocks:
              * self.dao.conn
              * self.dao.conn.commit
              * self.dao.get_latest_snapshot_timestamp
              * self.dao._create_snapshot_table

        Expect:
            * Assert that get_latest_snapshot_timestamp() gets called.
            * Assert that _create_snapshot_table() gets called.
            * Assert that conn.commit() is called 3x.
              was called == # of formatted/flattened RuleViolations).
        """

        conn_mock = mock.MagicMock()
        commit_mock = mock.MagicMock()

        self.dao.get_latest_snapshot_timestamp = mock.MagicMock(
            return_value = self.fake_snapshot_timestamp)
        self.dao._create_snapshot_table = mock.MagicMock(
            return_value=self.fake_table_name)
        self.dao.conn = conn_mock
        self.dao.execute_sql_with_commit = commit_mock

        self.dao.insert_violations(self.fake_violations,self.resource_name)

        # Assert snapshot is retrieved because no snapshot timestamp was
        # provided to the method call.
        self.dao.get_latest_snapshot_timestamp.assert_called_once_with(
            ('PARTIAL_SUCCESS', 'SUCCESS'))

        # Assert that the snapshot table was created.
        self.dao._create_snapshot_table.assert_called_once_with(
            self.resource_name, self.fake_snapshot_timestamp)

        # Assert that conn.commit() was called.
        self.assertEqual(3, commit_mock.call_count)

    def test_insert_violations_with_timestamp(self):
        """Test that insert_violations() is properly called with timestamp.

        Setup:
            * Create fake custom timestamp.
            * Create mocks:
                * self.dao._create_snapshot_table
                * self.dao.get_latest_snapshot_timestamp
                * self.dao.conn

        Expect:
            * Assert that get_latest_snapshot_timestamp() doesn't get called.
            * Assert that _create_snapshot_table() gets called once.
        """

        fake_custom_timestamp = '11111'
        self.dao.conn = mock.MagicMock()
        self.dao._create_snapshot_table = mock.MagicMock()
        self.dao.get_latest_snapshot_timestamp = mock.MagicMock()
        self.dao.insert_violations(self.fake_violations,
            self.resource_name,
            fake_custom_timestamp)

        self.dao.get_latest_snapshot_timestamp.assert_not_called()
        self.dao._create_snapshot_table.assert_called_once_with(
            self.resource_name, fake_custom_timestamp)

    def test_insert_violations_raises_error_on_create(self):
        """Test raises MySQLError when getting a create table error.
        
        Expect:
            Raise MySQLError when create_snapshot_table() raises an error.
        """

        self.dao.get_latest_snapshot_timestamp = mock.MagicMock(
            return_value=self.fake_snapshot_timestamp)
        self.dao._create_snapshot_table = mock.MagicMock(
            side_effect=MySQLdb.DataError)

        with self.assertRaises(errors.MySQLError):
            self.dao.insert_violations([], self.resource_name)

    def test_insert_violations_with_error(self):
        """Test insert_violations handles errors during insert.

        Setup:
            * Create mocks:
                * self.dao.conn
                * self.dao.get_latest_snapshot_timestamp
                * self.dao._create_snapshot_table
            * Create side effect for one violation to raise an error.
        
        Expect:
            * Log MySQLError when table insert error occurs and return list
              of errors.
            * Return a tuple of (num_violations-1, [violation])
        """

        self.dao.get_latest_snapshot_timestamp = mock.MagicMock(
            return_value=self.fake_snapshot_timestamp)
        self.dao._create_snapshot_table = mock.MagicMock(
            return_value=self.fake_table_name)
        violation_dao.LOGGER = mock.MagicMock()

        def insert_violation_side_effect(*args, **kwargs):
            if args[2] == self.expected_fake_violations[1]:
                raise MySQLdb.DataError(
                    self.resource_name, mock.MagicMock())
            else:
                return mock.DEFAULT

        self.dao.execute_sql_with_commit = mock.MagicMock(
            side_effect=insert_violation_side_effect)

        actual = self.dao.insert_violations(self.fake_violations,
            self.resource_name)
        expected = (2, [self.expected_fake_violations[1]])

        self.assertEqual(expected, actual)
        self.assertEquals(1, violation_dao.LOGGER.error.call_count)


if __name__ == '__main__':
    basetest.main()
