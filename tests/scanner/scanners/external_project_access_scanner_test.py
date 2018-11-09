# Copyright 2018 The Forseti Security Authors. All rights reserved.
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
"""Tests for ExternalProjectAccessScanner."""
# pylint: disable=line-too-long
from datetime import datetime
import json
# pylint says unittest goes before mock
import unittest
import mock

# pylint says sqlalchemy.orm goes before google.auth
from sqlalchemy.orm import sessionmaker

from google.cloud.forseti.common.gcp_type import resource_util
from google.cloud.forseti.common.gcp_type.folder import Folder
from google.cloud.forseti.common.gcp_type.organization import Organization
from google.cloud.forseti.common.gcp_type.project import Project
from google.cloud.forseti.common.gcp_type import resource as resource_mod
from google.cloud.forseti.common.util import logger
from google.cloud.forseti.scanner.audit.external_project_access_rules_engine import Rule
from google.cloud.forseti.scanner.scanners import external_project_access_scanner as epas
from google.cloud.forseti.services.inventory.storage import initialize
from google.cloud.forseti.services.inventory.storage import Storage
from tests.common.gcp_api.test_data import fake_crm_responses
from tests.services.api_tests.inventory_test import TestServiceConfig
from tests.services.inventory.storage_test import ResourceMock
from tests.services.util.db import create_test_engine
from tests.unittest_utils import ForsetiTestCase
from tests.unittest_utils import get_datafile_path
# pylint: enable=line-too-long

TEST_EMAILS = ['user1@example.com', 'user2@example.com']

LOGGER = logger.get_logger(__name__)


class ExternalProjectAccessScannerTest(ForsetiTestCase):
    """Tests for ExternalProjectAccessScanner"""

    def setUp(self):
        """Setup"""
        self.global_configs = dict()
        self.scanner_configs = (
            dict(output_path='gs://test-forseti-dev/scanner/output',
                 rules_path=__file__,
                 scanners=[dict(name='external_project_access', enabled=True)]))

        mock_invnetory_config = mock.MagicMock()
        mock_invnetory_config.get_root_resource_id.return_value = (
            'organizations/567890')

        mock_service_config = mock.MagicMock()
        mock_service_config.get_inventory_config.return_value = (
            mock_invnetory_config)

        self.service_config = mock_service_config
        self.model_name = 'TestModel'
        self.snapshot_timestamp = datetime.now().strftime('%Y%m%dT%H%M%SZ')
        self.rules = get_datafile_path(
            __file__, 'external_project_access_test_rules_1.yaml')

        self.stash_email_method = epas.get_user_emails

    @mock.patch('google.cloud.forseti.common.gcp_api.cloud_resource_manager.CloudResourceManagerClient')
    def test_get_project_ids(self, mock_crm_client):
        """Test get_projects_ids() for all lifecycle_states."""

        mock_crm_client.get_projects.return_value = (
            [fake_crm_responses.FAKE_PROJECTS_API_RESPONSE1])

        project_ids = epas.extract_project_ids(mock_crm_client)

        self.assertListEqual(
            fake_crm_responses.EXPECTED_FAKE_PROJECTS_API_RESPONSE1_IDS,
            project_ids)

    #pylint: disable=W0212
    @mock.patch('google.cloud.forseti.common.gcp_api.cloud_resource_manager.CloudResourceManagerClient')
    def test_retrieve(self, mock_crm_client):
        """Test retrieving project ancestry data"""
        list_to_generator = lambda x: (n for n in x)

        epas.get_user_emails = mock.MagicMock(return_value=TEST_EMAILS)

        scanner = epas.ExternalProjectAccessScanner(self.global_configs,
                                                    self.scanner_configs,
                                                    self.service_config,
                                                    self.model_name,
                                                    self.snapshot_timestamp,
                                                    self.rules)

        mock_crm_client.get_projects.return_value = list_to_generator(
            [fake_crm_responses.FAKE_PROJECTS_API_RESPONSE1])
        mock_crm_client.get_project_ancestry.return_value = json.loads(
                fake_crm_responses.GET_PROJECT_ANCESTRY_RESPONSE)['ancestor']
        
        scanner._get_crm_client = mock.MagicMock()
        scanner._get_crm_client.return_value = mock_crm_client

        scanner.rules_engine.build_rule_book(
            self.service_config.get_inventory_config())

        user_ancestries = scanner._retrieve()

        self.assertIn('user1@example.com', user_ancestries.keys())
        self.assertTrue(isinstance(user_ancestries['user1@example.com'], list))
        self.assertTrue(
            isinstance(user_ancestries['user1@example.com'][0], list))
        self.assertTrue(
            isinstance(user_ancestries['user1@example.com'][0][0], Project))

    def test_find_violations_bad_folder(self):
        """Test finding no violations with a bad folder as a parent"""
        epas.get_user_emails = mock.MagicMock(return_value=TEST_EMAILS)
        scanner = epas.ExternalProjectAccessScanner(self.global_configs,
                                                    self.scanner_configs,
                                                    self.service_config,
                                                    self.model_name,
                                                    self.snapshot_timestamp,
                                                    self.rules)

        scanner.rules_engine.build_rule_book(
            self.service_config.get_inventory_config())
        user_ancestries = {'user1@example.com': [[Project('1234'),
                                                  Organization('1234567')],
                                                 [Project('12345'),
                                                  Folder('ABCDEFG'),
                                                  Organization('1234567')]]}
        violations = scanner._find_violations(user_ancestries)
        self.assertEqual(len(violations), 0)

    def test_find_violations(self):
        """Test finding violations"""
        epas.get_user_emails = mock.MagicMock(return_value=TEST_EMAILS)
        scanner = epas.ExternalProjectAccessScanner(self.global_configs,
                                                    self.scanner_configs,
                                                    self.service_config,
                                                    self.model_name,
                                                    self.snapshot_timestamp,
                                                    self.rules)

        scanner.rules_engine.build_rule_book(
            self.service_config.get_inventory_config())
        user_ancestries = {'user1@example.com': [[Project('1234'),
                                                  Organization('1234567')],
                                                 [Project('12345'),
                                                  Folder('ABCDEFG'),
                                                  Organization('HIJKLMNOP')]]}
        violations = scanner._find_violations(user_ancestries)
        self.assertEqual(len(violations), 2)

    def test_flatten_violations(self):
        """Test flattening violations"""
        epas.get_user_emails = mock.MagicMock(return_value=TEST_EMAILS)
        violation1 = Rule.RuleViolation(
            resource_type=resource_mod.ResourceType.PROJECT,
            resource_id='12345',
            rule_name='Only my org',
            rule_index=0,
            rule_ancestors=[resource_util.create_resource(
                '45678', 'organization')],
            full_name='projects/12345',
            violation_type='EXTERNAL_PROJECT_ACCESS_VIOLATION',
            member='user1@example.com',
            resource_data=['projects/12345', 'organizations/67890'])

        scanner = epas.ExternalProjectAccessScanner(self.global_configs,
                                                    self.scanner_configs,
                                                    self.service_config,
                                                    self.model_name,
                                                    self.snapshot_timestamp,
                                                    self.rules)
        flattened_iter = scanner._flatten_violations([violation1])

        flat_violation = flattened_iter.next()
        self.assertEqual(flat_violation['resource_id'], '12345')
        self.assertEqual(
            flat_violation['resource_type'], resource_mod.ResourceType.PROJECT)
        self.assertEqual(flat_violation['rule_name'], 'Only my org')
        self.assertEqual(flat_violation['full_name'], 'projects/12345')
        self.assertEqual(
            flat_violation['violation_data']['member'], 'user1@example.com')

        with self.assertRaises(StopIteration):
            flat_violation = flattened_iter.next()

    def tearDown(self):
        epas.get_user_emails = self.stash_email_method


class GetUserEmailsTest(ForsetiTestCase):
    """Test the storage_helpers module."""
    def setUp(self):
        print("##AA#")
        self.engine = create_test_engine()
        _session_maker = sessionmaker()
        self.session = _session_maker(bind=self.engine)
        initialize(self.engine)
        res_user1 = ResourceMock('1', {'primaryEmail': 'user1@example.com',
                                       'suspended': False},
                                 'gsuite_user',
                                 'resource')
        res_user2 = ResourceMock('2', {'primaryEmail': 'user2@example.com',
                                       'suspended': False},
                                 'gsuite_user',
                                 'resource')
        res_user3 = ResourceMock('3', {'primaryEmail': 'user3@example.com',
                                       'suspended': False},
                                 'gsuite_user',
                                 'resource')
        self.resources = [res_user1, res_user2, res_user3]
        self.storage = Storage(self.session)
        _ = self.storage.open()
        for resource in self.resources:
            self.storage.write(resource)
        self.storage.commit()
        self.service_config = TestServiceConfig()

    #pylint: disable=C0301,W9016,W9015,W0613
    @mock.patch('google.cloud.forseti.scanner.scanners.external_project_access_scanner._get_inventory_storage')
    @mock.patch('google.cloud.forseti.services.inventory.storage.DataAccess.get_latest_inventory_index_id')
    def test_get_emails(self, mock_get_latest_inv_ndx_id, mock_storage):
        """Test retrieving e-mails from storage"""

        expected_emails = [u'user1@example.com',
                           u'user2@example.com',
                           u'user3@example.com']
        mock_storage.return_value = self.storage
        emails = epas.get_user_emails(self.service_config)
        self.assertListEqual(emails, expected_emails)

if __name__ == '__main__':
    unittest.main()
