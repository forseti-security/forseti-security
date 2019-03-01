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

"""Service Account Key Scanner Tests."""

import unittest
import mock
from datetime import datetime, timedelta

from tests import unittest_utils
from tests.services.util.db import create_test_engine
from google.cloud.forseti.scanner.scanners import service_account_key_scanner
from google.cloud.forseti.common.util.string_formats import DEFAULT_FORSETI_TIMESTAMP
from google.cloud.forseti.services.dao import ModelManager

"""
Assumptions: In data/service_account_key_test_rules.yaml, max_age is set to 
100 days.

Test: Create a service account with two keys, one 99 days old, one 101 days old.
The 101 day old key should be flagged as a violation but not the 99 day old.
"""

SERVICE_ACCOUNT_ID = '123456789012345678901'
SERVICE_ACCOUNT_NAME = 'projects/foo/serviceAccounts/test-service-account/test-service-account@developer.gserviceaccount.com'
SERVICE_ACCOUNT_DATA = """
{"displayName": "Service Account Key Age Test Service Account",
 "email": "test-service-account@developer.gserviceaccount.com",
 "name": "%s",
 "oauth2ClientId": "%s",
 "projectId": "foo",
 "uniqueId": "%s"}
""" % (SERVICE_ACCOUNT_NAME, SERVICE_ACCOUNT_ID, SERVICE_ACCOUNT_ID)

TIME_NOW = datetime.utcnow()

KEY_AGE_MORE_THAN_MAX_AGE = 101
KEY_DATETIME_MORE_THAN_MAX_AGE = TIME_NOW - timedelta(
    days=KEY_AGE_MORE_THAN_MAX_AGE)
KEY_TIME_MORE_THAN_MAX_AGE = KEY_DATETIME_MORE_THAN_MAX_AGE.strftime(
    DEFAULT_FORSETI_TIMESTAMP)

KEY_AGE_LESS_THAN_MAX_AGE = 99
KEY_DATETIME_LESS_THAN_MAX_AGE = TIME_NOW - timedelta(
    days=KEY_AGE_LESS_THAN_MAX_AGE)
KEY_TIME_LESS_THAN_MAX_AGE = KEY_DATETIME_LESS_THAN_MAX_AGE.strftime(
    DEFAULT_FORSETI_TIMESTAMP)

# Not used in checking but populate anyway
VALID_BEFORE_TIME = (TIME_NOW + timedelta(days=3650)).strftime(
    DEFAULT_FORSETI_TIMESTAMP)

ROTATED_KEY_ID = '111111111111111111111'
ROTATED_KEY_NAME = SERVICE_ACCOUNT_NAME + '/keys/' + ROTATED_KEY_ID
ROTATED_KEY_DATA = """
{"keyAlgorithm": "KEY_ALG_RSA_2048",
 "name": "%s",
 "validAfterTime": "%s",
 "validBeforeTime": "%s"}
""" % (ROTATED_KEY_NAME, KEY_TIME_LESS_THAN_MAX_AGE, VALID_BEFORE_TIME)

UN_ROTATED_KEY_ID = '999999999999999999999'
UN_ROTATED_KEY_NAME = SERVICE_ACCOUNT_NAME + '/keys/' + UN_ROTATED_KEY_ID
UN_ROTATED_KEY_DATA = """
{"keyAlgorithm": "KEY_ALG_RSA_2048",
 "name": "%s",
 "validAfterTime": "%s",
 "validBeforeTime": "%s"}
""" % (UN_ROTATED_KEY_NAME, KEY_TIME_MORE_THAN_MAX_AGE, VALID_BEFORE_TIME)

RESOURCE_DATA = ('{"full_name": "organization/12345/project/foo/serviceaccount/'
                 '123456789012345678901/serviceaccount_key/'
                 '999999999999999999999/", '
                 '"key_algorithm": "KEY_ALG_RSA_2048", '
                 '"key_id": "999999999999999999999", '
                 '"valid_after_time": "%s", '
                 '"valid_before_time": "%s"}') % (KEY_TIME_MORE_THAN_MAX_AGE,
                                                  VALID_BEFORE_TIME)

EXPECTED_VIOLATION = {'rule_name': 'Service account keys not rotated (older than 100 days)',
                      'resource_data': RESOURCE_DATA,
                      'full_name': u'organization/12345/project/foo/serviceaccount/123456789012345678901/serviceaccount_key/999999999999999999999/',
                      'resource_name': u'test-service-account@developer.gserviceaccount.com',
                      'resource_id': u'test-service-account@developer.gserviceaccount.com',
                      'rule_index': 0,
                      'violation_type': 'SERVICE_ACCOUNT_KEY_VIOLATION',
                      'violation_data': {
                          'service_account_name': u'Service Account Key Age Test Service Account',
                          'service_account_id': u'test-service-account@developer.gserviceaccount.com',
                          'violation_reason': u'Key ID 999999999999999999999 not rotated since %s.' % KEY_TIME_MORE_THAN_MAX_AGE,
                          'key_id': u'999999999999999999999',
                          'project_id': u'foo',
                          'key_created_time': u'%s' % KEY_TIME_MORE_THAN_MAX_AGE},
                      'resource_type': 'serviceaccount_key'
                      }


class FakeServiceConfig(object):

    def __init__(self):
        engine = create_test_engine()
        self.model_manager = ModelManager(engine)


# pylint: disable=bad-indentation
class ServiceAccountKeyScannerTest(unittest_utils.ForsetiTestCase):

    @classmethod
    def setUpClass(cls):
        cls.service_config = FakeServiceConfig()
        cls.model_name = cls.service_config.model_manager.create(
            name='service-account-key-scanner-test')

        scoped_session, data_access = (
            cls.service_config.model_manager.get(cls.model_name))

        # Add organization and project to model.
        with scoped_session as session:
            organization = data_access.add_resource_by_name(
                session, 'organization/12345', '', True)
            project = data_access.add_resource(session, 'project/foo',
                                               organization)
            service_account = data_access.add_resource(
                session, 'serviceaccount/%s' % SERVICE_ACCOUNT_ID,
                project)
            service_account.data = SERVICE_ACCOUNT_DATA

            # Add both, the rotated and un-rotated keys to the above
            rotated_key = data_access.add_resource(
                session, 'serviceaccount_key/%s' % ROTATED_KEY_ID,
                service_account)
            rotated_key.data = ROTATED_KEY_DATA

            un_rotated_key = data_access.add_resource(
                session, 'serviceaccount_key/%s' % UN_ROTATED_KEY_ID,
                service_account)
            un_rotated_key.data = UN_ROTATED_KEY_DATA

            session.commit()

    def setUp(self):

        self.scanner = service_account_key_scanner.ServiceAccountKeyScanner(
            {}, {}, self.service_config, self.model_name,
            '', unittest_utils.get_datafile_path(
                __file__, 'service_account_key_test_rules.yaml'))

    @mock.patch.object(
        service_account_key_scanner.ServiceAccountKeyScanner,
        '_output_results_to_db', autospec=True)
    def test_run_scanner(self, mock_output_results):
        self.scanner.run()
        expected_violations = [EXPECTED_VIOLATION,]
        mock_output_results.assert_called_once_with(mock.ANY,
                                                    expected_violations)


if __name__ == '__main__':
    unittest.main()
