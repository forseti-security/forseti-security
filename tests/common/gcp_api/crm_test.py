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

"""Tests the Cloud Resource Manager API client."""

import json
import unittest
import mock
from oauth2client import client

from tests.common.gcp_api.test_data import fake_crm_responses
from tests.common.gcp_api.test_data import http_mocks
from tests.common.gcp_type.test_data import fake_folders
from tests.common.gcp_type.test_data import fake_orgs
from tests.common.gcp_type.test_data import fake_projects
from tests.unittest_utils import ForsetiTestCase
from google.cloud.security.common.gcp_api import cloud_resource_manager as crm
from google.cloud.security.common.gcp_api import errors as api_errors
from google.cloud.security.common.gcp_type.resource import LifecycleState


class CloudResourceManagerTest(ForsetiTestCase):
    """Test the Cloud Resource Manager API Client."""

    @mock.patch.object(client, 'GoogleCredentials', spec=True)
    def setUp(self, mock_google_credential):
        """Set up."""
        fake_global_configs = {
            'max_crm_api_calls_per_100_seconds': 1000000}
        self.crm_api_client = crm.CloudResourceManagerClient(
            global_configs=fake_global_configs, use_rate_limiter=False)

        self.project_id = fake_crm_responses.FAKE_PROJECT_ID

    @mock.patch.object(client, 'GoogleCredentials')
    def test_no_quota(self, mock_google_credential):
        """Verify no rate limiter is used if the configuration is missing."""
        crm_api_client = crm.CloudResourceManagerClient(global_configs={})
        self.assertEqual(None, crm_api_client.repository._rate_limiter)

    def test_get_project(self):
        """Test can get project."""
        http_mocks.mock_http_response(fake_crm_responses.GET_PROJECT_RESPONSE)
        response = self.crm_api_client.get_project(self.project_id)

        self.assertEqual(self.project_id, response.get('projectId'))

    def test_get_project_error(self):
        """Test the error handling."""
        http_mocks.mock_http_response(fake_crm_responses.GET_PROJECT_NOT_FOUND,
                                      '403')

        with self.assertRaises(api_errors.ApiExecutionError):
            self.crm_api_client.get_project(self.project_id)

    def test_get_projects_active(self):
        """Test get_projects() for ACTIVE projects."""
        response = json.dumps(fake_projects.FAKE_ACTIVE_PROJECTS_API_RESPONSE)
        http_mocks.mock_http_response(response)

        result = list(self.crm_api_client.get_projects(
            'projects', lifecycleState=LifecycleState.ACTIVE))
        self.assertEquals(fake_projects.EXPECTED_FAKE_ACTIVE_PROJECTS1, result)

    def test_get_projects_all(self):
        """Test get_projects() for all lifecycle_states."""
        response = json.dumps(fake_projects.FAKE_PROJECTS_API_RESPONSE1)
        http_mocks.mock_http_response(response)

        result = list(self.crm_api_client.get_projects('projects'))
        self.assertEquals(fake_projects.EXPECTED_FAKE_PROJECTS1, result)

    def test_get_projects_api_error(self):
        """Test get_projects() raises ApiExecutionError on HTTP error."""
        http_mocks.mock_http_response(fake_crm_responses.GET_PROJECT_NOT_FOUND,
                                      '403')

        with self.assertRaises(api_errors.ApiExecutionError):
            list(self.crm_api_client.get_projects('projects'))

    def test_get_project_iam_policies(self):
        """Test get project IAM policies."""
        http_mocks.mock_http_response(fake_crm_responses.GET_IAM_POLICY)

        response = self.crm_api_client.get_project_iam_policies('foo',
                                                                self.project_id)
        self.assertTrue('bindings' in response)

    def test_get_project_iam_policies_errors(self):
        """Test the error handling."""
        http_mocks.mock_http_response(fake_crm_responses.GET_PROJECT_NOT_FOUND,
                                      '403')

        with self.assertRaises(api_errors.ApiExecutionError):
            self.crm_api_client.get_project_iam_policies('foo', self.project_id)

    def test_get_organization(self):
        """Test get single organization."""
        http_mocks.mock_http_response(fake_crm_responses.GET_ORGANIZATION)
        org_id = fake_crm_responses.FAKE_ORG_ID

        response = self.crm_api_client.get_organization(org_id)
        self.assertEqual('organizations/{}'.format(org_id),
                         response.get('name'))

    def test_get_organization_raises_error(self):
        """Test get_organization() raises ApiExecutionError on HTTP error."""
        http_mocks.mock_http_response(fake_crm_responses.GET_PROJECT_NOT_FOUND, '403')

        with self.assertRaises(api_errors.ApiExecutionError):
            self.crm_api_client.get_organization(fake_crm_responses.FAKE_ORG_ID)

    def test_get_organizations(self):
        """Test get organizations."""
        fake_orgs_response = json.dumps(fake_orgs.FAKE_ORGS_RESPONSE)
        http_mocks.mock_http_response(fake_orgs_response)
        expected_orgs = fake_orgs.EXPECTED_FAKE_ORGS_FROM_API

        result = list(self.crm_api_client.get_organizations('organizations'))
        self.assertEquals(expected_orgs, result)

    def test_get_organizations_raises_error(self):
        """Test get_organizations() raises ApiExecutionError on HTTP error."""
        http_mocks.mock_http_response(fake_crm_responses.GET_PROJECT_NOT_FOUND,
                                      '403')

        with self.assertRaises(api_errors.ApiExecutionError):
            list(self.crm_api_client.get_organizations('organizations'))

    def test_get_org_iam_policies(self):
        """Test get org IAM policies."""
        http_mocks.mock_http_response(fake_crm_responses.GET_IAM_POLICY)
        org_id = fake_crm_responses.FAKE_ORG_ID

        response = self.crm_api_client.get_org_iam_policies(
            'organizations', org_id)

        self.assertTrue('bindings' in response.get('iam_policy', {}),
                        msg='Response {} does not contain "bindings".'.format(
                            response))

    def test_get_org_iam_policies_raises_error(self):
        """Test get_org_iam_policies() raises ApiExecutionError on error."""
        http_mocks.mock_http_response(fake_crm_responses.GET_PROJECT_NOT_FOUND,
                                      '403')

        with self.assertRaises(api_errors.ApiExecutionError):
            self.crm_api_client.get_org_iam_policies('foo', self.project_id)

    def test_get_folder(self):
        """Test get_folder()."""
        http_mocks.mock_http_response(fake_crm_responses.GET_FOLDER)
        folder_id = fake_crm_responses.FAKE_FOLDER_ID

        response = self.crm_api_client.get_folder(folder_id)
        self.assertEqual('folders/{}'.format(folder_id),
                         response.get('name'))

    def test_get_folder_raises_error(self):
        """Test get_folder() raises ApiExecutionError when HTTP error occurs."""
        http_mocks.mock_http_response(fake_crm_responses.GET_PROJECT_NOT_FOUND,
                                      '403')

        with self.assertRaises(api_errors.ApiExecutionError):
            self.crm_api_client.get_folder(fake_crm_responses.FAKE_FOLDER_ID)

    def test_get_folders_all(self):
        """Test get_folders()."""
        fake_folders_response = json.dumps(
            fake_folders.FAKE_FOLDERS_API_RESPONSE1)
        http_mocks.mock_http_response(fake_folders_response)
        expected_folders = fake_folders.EXPECTED_FAKE_FOLDERS1

        result = list(self.crm_api_client.get_folders('folders'))
        self.assertEquals(expected_folders, result)

    def test_get_folders_active(self):
        """Test get_folders() only for lifecycle_state=ACTIVE."""

        fake_folders_response = json.dumps(
            fake_folders.FAKE_ACTIVE_FOLDERS_API_RESPONSE1)
        http_mocks.mock_http_response(fake_folders_response)

        expected_folders = fake_folders.EXPECTED_FAKE_ACTIVE_FOLDERS1

        result = list(self.crm_api_client.get_folders(
            'folders', lifecycle_state='ACTIVE'))
        self.assertEquals(expected_folders, result)

    def test_get_folders_raises_error(self):
        """Test get_folders() raises ApiExecutionError on HTTP error."""
        http_mocks.mock_http_response(fake_crm_responses.GET_PROJECT_NOT_FOUND,
                                      '403')

        with self.assertRaises(api_errors.ApiExecutionError):
            list(self.crm_api_client.get_folders('folders'))

    def test_get_folder_iam_policies(self):
        """Test get folder IAM policies."""
        http_mocks.mock_http_response(fake_crm_responses.GET_IAM_POLICY)
        folder_id = fake_crm_responses.FAKE_FOLDER_ID

        response = self.crm_api_client.get_folder_iam_policies('foo', folder_id)

        self.assertTrue('bindings' in response.get('iam_policy', {}),
                        msg='Response {} does not contain "bindings".'.format(
                            response))

    def test_get_folder_iam_policies_raises_error(self):
        """Test get_folder_iam_policies() raises ApiExecutionError."""
        http_mocks.mock_http_response(fake_crm_responses.GET_PROJECT_NOT_FOUND,
                                      '403')

        with self.assertRaises(api_errors.ApiExecutionError):
            self.crm_api_client.get_folder_iam_policies(
                'foo', fake_crm_responses.FAKE_FOLDER_ID)


if __name__ == '__main__':
    unittest.main()
