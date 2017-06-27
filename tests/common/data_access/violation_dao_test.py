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

from tests.unittest_utils import ForsetiTestCase
import mock
import MySQLdb
import json

from google.cloud.security.common.data_access import _db_connector
from google.cloud.security.common.data_access import errors
from google.cloud.security.common.data_access import violation_dao
from google.cloud.security.common.data_access import violation_map as vm
from google.cloud.security.common.data_access.sql_queries import load_data
from google.cloud.security.common.gcp_type import iam_policy as iam
from google.cloud.security.scanner.audit import rules
from google.cloud.security.scanner import scanner

def _flatten_violations(violations, flattening_scheme):
    """Flatten RuleViolations into a dict for each RuleViolation member.

    Args:
        violations: The RuleViolations to flatten.
        flattening_scheme: Which flattening scheme to use

    Yield:
        Iterator of RuleViolations as a dict per member.
    """
    for violation in violations:
        if flattening_scheme == 'policy_violations':
            for member in violation.members:
                violation_data = {}
                violation_data['role'] = violation.role
                violation_data['member'] = '{}:{}'.format(member.type,
                                                          member.name)
                yield {
                    'resource_id': violation.resource_id,
                    'resource_type': violation.resource_type,
                    'rule_index': violation.rule_index,
                    'rule_name': violation.rule_name,
                    'violation_type': violation.violation_type,
                    'violation_data': violation_data
                }
        if flattening_scheme == 'buckets_acl_violations':
            violation_data = {}
            violation_data['role'] = violation.role
            violation_data['entity'] = violation.entity
            violation_data['email'] = violation.email
            violation_data['domain'] = violation.domain
            violation_data['bucket'] = violation.bucket
            yield {
                'resource_id': violation.resource_id,
                'resource_type': violation.resource_type,
                'rule_index': violation.rule_index,
                'rule_name': violation.rule_name,
                'violation_type': violation.violation_type,
                'violation_data': violation_data
            }
        if flattening_scheme == 'cloudsql_acl_violations':
            violation_data = {}
            violation_data['instance_name'] = violation.instance_name
            violation_data['authorized_networks'] = violation.authorized_networks
            violation_data['ssl_enabled'] = violation.ssl_enabled
            yield {
                'resource_id': violation.resource_id,
                'resource_type': violation.resource_type,
                'rule_index': violation.rule_index,
                'rule_name': violation.rule_name,
                'violation_type': violation.violation_type,
                'violation_data': violation_data
            }
        if flattening_scheme == 'bigquery_acl_violations':
            violation_data = {}
            violation_data['dataset_id'] = violation.dataset_id
            violation_data['access_domain'] = violation.domain
            violation_data['access_user_by_email'] = violation.user_email
            violation_data['access_special_group'] = violation.special_group
            violation_data['access_group_by_email'] = violation.group_email
            violation_data['role'] = violation.role
            yield {
                'resource_id': violation.resource_id,
                'resource_type': violation.resource_type,
                'rule_index': violation.rule_index,
                'rule_name': violation.rule_name,
                'violation_type': violation.violation_type,
                'violation_data': violation_data
            }


class ViolationDaoTest(ForsetiTestCase):
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
                resource_type='%se' % ('a'*300),
                resource_id='1',
                rule_name='%sh' % ('b'*300),
                rule_index=1,
                violation_type='REMOVED',
                role='%s' % ('c'*300),
                members=[iam.IamPolicyMember.create_from(
                    'user:%s' % ('d'*300))],
            ),
        ]
        long_string = '{"member": "user:%s", "role": "%s"}' % (('d'*300),('c'*300))

        self.expected_fake_violations = [
            ('x', '1', 'rule name', 0, 'ADDED',
             '{"member": "user:a@foo.com", "role": "roles/editor"}'),
            ('x', '1', 'rule name', 0, 'ADDED',
             '{"member": "user:b@foo.com", "role": "roles/editor"}'),
            ('a'*255, '1', 'b'*255, 1, 'REMOVED', long_string),
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
        resource_name = 'policy_violations'
        flattened_fake_violations = scanner._flatten_violations(
                                                          self.fake_violations,
                                                          resource_name)

        temp_actual = []
        actual = []
        for violation in flattened_fake_violations:
            violation = violation_dao.ViolationDao.Violation(
                                  resource_type=violation['resource_type'],
                                  resource_id=violation['resource_id'],
                                  rule_name=violation['rule_name'],
                                  rule_index=violation['rule_index'],
                                  violation_type=violation['violation_type'],
                                  violation_data=violation['violation_data'])
            temp = violation_dao._format_violation(violation, 
                                                   self.resource_name)
            temp_actual.append(temp)

        for a in temp_actual:
            actual.append(a.next())
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
        resource_name = 'policy_violations'
        conn_mock = mock.MagicMock()
        commit_mock = mock.MagicMock()

        self.dao.get_latest_snapshot_timestamp = mock.MagicMock(
            return_value = self.fake_snapshot_timestamp)
        self.dao._create_snapshot_table = mock.MagicMock(
            return_value=self.fake_table_name)
        self.dao.conn = conn_mock
        self.dao.execute_sql_with_commit = commit_mock
        flattened_fake_violations = scanner._flatten_violations(
                                                          self.fake_violations,
                                                          resource_name)
        self.dao.insert_violations(flattened_fake_violations,
                                   self.resource_name)

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
        flattened_fake_violations = scanner._flatten_violations(
                                                          self.fake_violations,
                                                          self.resource_name)
        self.dao.insert_violations(flattened_fake_violations,
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
        resource_name = 'policy_violations'
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
        
        flattened_fake_violations = scanner._flatten_violations(
                                                          self.fake_violations,
                                                          resource_name)
        actual = self.dao.insert_violations(flattened_fake_violations,
            self.resource_name)

        expected = (2, [self.expected_fake_violations[1]])

        self.assertEqual(expected, actual)
        self.assertEquals(1, violation_dao.LOGGER.error.call_count)


if __name__ == '__main__':
    unittest.main()
