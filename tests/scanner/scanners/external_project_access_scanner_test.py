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
from datetime import datetime
import json
import unittest
import mock

import google.auth
from google.oauth2 import credentials
from sqlalchemy.orm import sessionmaker

from google.cloud.forseti.common.gcp_api import cloud_resource_manager as crm
from google.cloud.forseti.common.gcp_type import resource_util
from google.cloud.forseti.common.gcp_type.folder import Folder
from google.cloud.forseti.common.gcp_type.organization import Organization
from google.cloud.forseti.common.gcp_type.project import Project
from google.cloud.forseti.common.util import logger
from google.cloud.forseti.scanner.audit import errors as audit_errors
from google.cloud.forseti.scanner.scanners import external_project_access_scanner as epas
from google.cloud.forseti.services import db
from google.cloud.forseti.services.inventory.storage import initialize
from google.cloud.forseti.services.inventory.storage import Storage
from tests.common.gcp_api.test_data import fake_crm_responses
from tests.common.gcp_api.test_data import http_mocks
from tests.services.api_tests.inventory_test import TestServiceConfig
from tests.services.inventory.storage_test import ResourceMock
from tests.services.util.db import create_test_engine
from tests.unittest_utils import ForsetiTestCase
from tests.unittest_utils import get_datafile_path


TEST_EMAILS = ['user1@example.com', 'user2@example.com']

LOGGER = logger.get_logger(__name__)


class ExternalProjectAccessScannerTest(ForsetiTestCase):
    
    def setUp(self):

        self.global_configs = dict()
        self.scanner_configs = dict(output_path="gs://test-forseti-dev/scanner/output",
                                    rules_path=__file__,
                                    scanners=[dict(name='external_project_access', enabled=True)])

        mock_invnetory_config = mock.MagicMock()
        mock_invnetory_config.get_root_resource_id.return_value = 'organizations/567890'

        mock_service_config = mock.MagicMock()
        mock_service_config.get_inventory_config.return_value = mock_invnetory_config
        
        self.service_config = mock_service_config
        self.model_name = "TestModel"
        self.snapshot_timestamp = datetime.now().strftime("%Y%m%dT%H%M%SZ")
        self.rules = get_datafile_path(__file__, 'external_project_access_test_rules_1.yaml')

    @mock.patch("google.cloud.forseti.scanner.scanners.external_project_access_scanner.get_user_emails", return_value=TEST_EMAILS)
    def test_mock_emails(self, mock_get_emails):
        self.assertEqual(len(epas.get_user_emails(None)), 2)

    @mock.patch("google.cloud.forseti.common.gcp_api.cloud_resource_manager.CloudResourceManagerClient.get_projects")
    @mock.patch("google.cloud.forseti.common.gcp_api.cloud_resource_manager.CloudResourceManagerClient.get_project_ancestry")
    @mock.patch("google.cloud.forseti.scanner.scanners.external_project_access_scanner.extract_project_ids")
    @mock.patch("google.cloud.forseti.common.gcp_api.api_helpers.get_delegated_credential")
    @mock.patch("google.cloud.forseti.scanner.scanners.external_project_access_scanner.get_user_emails", return_value=TEST_EMAILS)
    def test_retrieve(self, mock_emails, mock_credential, mock_ids, mock_ancestry, mock_get_projects):
        
        list_to_generator = lambda x : (n for n in x)
        mock_get_projects.return_value = list_to_generator([fake_crm_responses.FAKE_PROJECTS_API_RESPONSE1])
        mock_ids.return_value = ['project1', 'project2', 'project3']

        mock_ancestry.return_value = json.loads(fake_crm_responses.GET_PROJECT_ANCESTRY_RESPONSE)['ancestor']

        scanner = epas.ExternalProjectAccessScanner(self.global_configs,
                                                    self.scanner_configs,
                                                    self.service_config,
                                                    self.model_name,
                                                    self.snapshot_timestamp,
                                                    self.rules)
        scanner.rules_engine.build_rule_book(self.service_config.get_inventory_config())

        user_ancestries = scanner._retrieve()

        self.assertIn("user1@example.com", user_ancestries.keys())
        self.assertTrue(isinstance(user_ancestries['user1@example.com'], list))
        self.assertTrue(isinstance(user_ancestries['user1@example.com'][0], list))
        self.assertTrue(isinstance(user_ancestries['user1@example.com'][0][0], Project))

    @mock.patch("google.cloud.forseti.scanner.scanners.external_project_access_scanner.get_user_emails", return_value=TEST_EMAILS)
    def test_find_violations_bad_folder(self, mock_emails):
        scanner = epas.ExternalProjectAccessScanner(self.global_configs,
                                                    self.scanner_configs,
                                                    self.service_config,
                                                    self.model_name,
                                                    self.snapshot_timestamp,
                                                    self.rules)

        scanner.rules_engine.build_rule_book(self.service_config.get_inventory_config())
        user_ancestries = {"user1@example.com": [[Project("1234"), Organization("1234567")],
                                                 [Project("12345"), Folder("ABCDEFG"), Organization("1234567")]]}
        violations = scanner._find_violations(user_ancestries)
        self.assertEqual(len(violations), 0)

    @mock.patch("google.cloud.forseti.scanner.scanners.external_project_access_scanner.get_user_emails", return_value=TEST_EMAILS)
    def test_find_violations_bad_ancestry(self, mock_emails):
        scanner = epas.ExternalProjectAccessScanner(self.global_configs,
                                                    self.scanner_configs,
                                                    self.service_config,
                                                    self.model_name,
                                                    self.snapshot_timestamp,
                                                    self.rules)

        scanner.rules_engine.build_rule_book(self.service_config.get_inventory_config())
        user_ancestries = {"user1@example.com": [[Project("1234"), Organization("1234567")],
                                                 [Project("12345"), Folder("ABCDEFG"), Organization("HIJKLMNOP")]]}
        violations = scanner._find_violations(user_ancestries)
        self.assertEqual(len(violations), 2)

    @mock.patch("google.cloud.forseti.scanner.scanners.external_project_access_scanner.get_user_emails", return_value=TEST_EMAILS)
    def test_find_violations_all_good(self, mock_emails):
        scanner = epas.ExternalProjectAccessScanner(self.global_configs,
                                                    self.scanner_configs,
                                                    self.service_config,
                                                    self.model_name,
                                                    self.snapshot_timestamp,
                                                    self.rules)
        scanner.rules_engine.build_rule_book(self.service_config.get_inventory_config())

        user_ancestries = {"user1@example.com": [[Project("1234"), Organization("1234567")]]}
        violations = scanner._find_violations(user_ancestries)
        self.assertEqual(len(violations), 0)


class GetUserEmailsTest(ForsetiTestCase):
    """Test the storage_helpers modue."""

    def setUp(self):
        self.engine = create_test_engine()

        _session_maker = sessionmaker()
        self.session = _session_maker(bind=self.engine)
        initialize(self.engine)

        res_user1 = ResourceMock('1', {"primaryEmail": "user1@example.com", "suspended": False},
                                        'gsuite_user', 
                                        'resource')
        res_user2 = ResourceMock('2', {"primaryEmail": "user2@example.com", "suspended": False}, 
                                        'gsuite_user', 
                                        'resource')
        res_user3 = ResourceMock('3', {"primaryEmail": "user3@example.com", "suspended": False}, 
                                        'gsuite_user', 
                                        'resource')

        self.resources = [res_user1, res_user2, res_user3]

        self.storage = Storage(self.session)
        inv_index_id = self.storage.open()
        for resource in self.resources:
            self.storage.write(resource)
        self.storage.commit()

        self.service_config = TestServiceConfig()
    
    @mock.patch("google.cloud.forseti.scanner.scanners.external_project_access_scanner._get_inventory_storage")
    @mock.patch("google.cloud.forseti.services.inventory.storage.DataAccess.get_latest_inventory_index_id")
    def test_get_emails(self, mock_get_latest_inv_ndx_id, mock_storage):
        expected_emails = [u'user1@example.com', u'user2@example.com', u'user3@example.com']
        mock_storage.return_value = self.storage
        emails = epas.get_user_emails(self.service_config)
        self.assertListEqual(emails, expected_emails)


class OtherModuleTest(ForsetiTestCase):

    @classmethod
    @mock.patch.object(
        google.auth, 'default',
        return_value=(mock.Mock(spec_set=credentials.Credentials),
                      'test-project'))
    def setUpClass(cls, mock_google_credential):
        """Set up."""
        fake_global_configs = {
            'crm': {'max_calls': 4, 'period': 1.2}}
        cls.crm_api_client = crm.CloudResourceManagerClient(
            global_configs=fake_global_configs, use_rate_limiter=False)
        cls.project_id = fake_crm_responses.FAKE_PROJECT_ID 

    def test_get_project_ids(self):
        """Test get_projects_ids() for all lifecycle_states."""
        response = json.dumps(fake_crm_responses.FAKE_PROJECTS_API_RESPONSE1)
        http_mocks.mock_http_response(response)

        #result = self.crm_api_client.get_projects()
        proj_ids = epas.extract_project_ids(self.crm_api_client)

        self.assertListEqual(proj_ids, 
                             fake_crm_responses.EXPECTED_FAKE_PROJECTS_API_RESPONSE1_IDS)

    def test_cast_to_gcp_resources(self):
        """Validate get_project_ancestry_resources() with test project."""
        http_mocks.mock_http_response(
            fake_crm_responses.GET_PROJECT_ANCESTRY_RESPONSE)
        result = self.crm_api_client.get_project_ancestry(
            fake_crm_responses.FAKE_PROJECT_ID)

        cast_resources = resource_util.cast_to_gcp_resources(result)
        
        self.assertTrue(isinstance(cast_resources, list))

        self.assertTrue(isinstance(cast_resources[0], Project))
        self.assertTrue(isinstance(cast_resources[-1], Organization))


if __name__ == '__main__':
    unittest.main()
