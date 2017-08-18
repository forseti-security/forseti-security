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
from googleapiclient.http import HttpMock
from httplib2 import HttpLib2Error
import mock

from tests.common.gcp_api.test_data import fake_crm_responses
from tests.common.gcp_type.test_data import fake_folders
from tests.common.gcp_type.test_data import fake_orgs
from tests.common.gcp_type.test_data import fake_projects
from tests.unittest_utils import ForsetiTestCase
from google.cloud.security.common.gcp_api import _base_repository
from google.cloud.security.common.gcp_api import cloud_resource_manager as crm
from google.cloud.security.common.gcp_api import errors as api_errors
from google.cloud.security.common.gcp_type.resource import LifecycleState


# pylint: disable=bad-indentation
class CloudResourceManagerTest(ForsetiTestCase):
    """Test the Cloud Resource Manager API Client."""

    MAX_CRM_API_CALLS_PER_100_SECONDS = 88888

    @mock.patch('google.cloud.security.common.gcp_api._base_repository'
                '.GoogleCredentials')
    def setUp(self, mock_google_credential):
        """Set up."""
        fake_global_configs = {
            'max_crm_api_calls_per_100_seconds':
                self.MAX_CRM_API_CALLS_PER_100_SECONDS}
        self.crm_api_client = crm.CloudResourceManagerClient(
            global_configs=fake_global_configs)

        self.project_id = fake_crm_responses.FAKE_PROJECT_ID

    def mock_http_response(self, response, status='200'):
        """Set the mock response to an http request."""
        http_mock = HttpMock()
        http_mock.response_headers = {'status': status}
        http_mock.data = response
        _base_repository.LOCAL_THREAD.http = http_mock

    def test_get_project(self):
        """Test can get project."""
        self.mock_http_response(fake_crm_responses.GET_PROJECT_RESPONSE)
        response = self.crm_api_client.get_project(self.project_id)

        self.assertEqual(self.project_id, response.get('projectId'))

    def test_get_project_error(self):
        """Test the error handling."""
        self.mock_http_response(fake_crm_responses.GET_PROJECT_NOT_FOUND, '403')

        with self.assertRaises(api_errors.ApiExecutionError):
            self.crm_api_client.get_project(self.project_id)

    def test_get_projects_active(self):
        """Test get_projects() for ACTIVE projects."""
        response = json.dumps(fake_projects.FAKE_ACTIVE_PROJECTS_API_RESPONSE)
        self.mock_http_response(response)

        result = list(self.crm_api_client.get_projects(
            'projects', lifecycleState=LifecycleState.ACTIVE))
        self.assertEquals(fake_projects.EXPECTED_FAKE_ACTIVE_PROJECTS1, result)

    def test_get_projects_all(self):
        """Test get_projects() for all lifecycle_states."""
        response = json.dumps(fake_projects.FAKE_PROJECTS_API_RESPONSE1)
        self.mock_http_response(response)

        result = list(self.crm_api_client.get_projects('projects'))
        self.assertEquals(fake_projects.EXPECTED_FAKE_PROJECTS1, result)

    def test_get_projects_api_error(self):
        """Test get_projects() raises ApiExecutionError on HTTP error."""
        self.mock_http_response(fake_crm_responses.GET_PROJECT_NOT_FOUND, '403')

        with self.assertRaises(api_errors.ApiExecutionError):
            list(self.crm_api_client.get_projects('projects'))

    def test_get_project_iam_policies(self):
        """Test get project IAM policies."""
        self.mock_http_response(fake_crm_responses.GET_IAM_POLICY)

        response = self.crm_api_client.get_project_iam_policies('foo',
                                                                self.project_id)
        self.assertTrue('bindings' in response)

    def test_get_project_iam_policies_errors(self):
        """Test the error handling."""
        self.mock_http_response(fake_crm_responses.GET_PROJECT_NOT_FOUND, '403')

        with self.assertRaises(api_errors.ApiExecutionError):
            self.crm_api_client.get_project_iam_policies('foo', self.project_id)

    def test_get_organization(self):
        """Test get single organization."""
        self.mock_http_response(fake_crm_responses.GET_ORGANIZATION)
        org_id = fake_crm_responses.FAKE_ORG_ID

        response = self.crm_api_client.get_organization(org_id)
        self.assertEqual('organizations/{}'.format(org_id),
                         response.get('name'))

    def test_get_organization_raises_error(self):
        """Test get_organization() raises ApiExecutionError on HTTP error."""
        self.mock_http_response(fake_crm_responses.GET_PROJECT_NOT_FOUND, '403')

        with self.assertRaises(api_errors.ApiExecutionError):
            self.crm_api_client.get_organization(fake_crm_responses.FAKE_ORG_ID)

    def test_get_organizations(self):
        """Test get organizations."""
        fake_orgs_response = json.dumps(fake_orgs.FAKE_ORGS_RESPONSE)
        self.mock_http_response(fake_orgs_response)
        expected_orgs = fake_orgs.EXPECTED_FAKE_ORGS_FROM_API

        self.mock_http_response(fake_orgs_response)

        result = list(self.crm_api_client.get_organizations('organizations'))
        self.assertEquals(expected_orgs, result)

    def test_get_organizations_raises_error(self):
        """Test get_organizations() raises ApiExecutionError on HTTP error."""
        self.mock_http_response(fake_crm_responses.GET_PROJECT_NOT_FOUND, '403')

        with self.assertRaises(api_errors.ApiExecutionError):
            list(self.crm_api_client.get_organizations('organizations'))

    def test_get_org_iam_policies(self):
        """Test get org IAM policies."""
        self.mock_http_response(fake_crm_responses.GET_IAM_POLICY)
        org_id = fake_crm_responses.FAKE_ORG_ID

        response = self.crm_api_client.get_org_iam_policies(
            'organizations', org_id)

        self.assertTrue('bindings' in response.get('iam_policy', {}),
                        msg='Response {} does not contain "bindings".'.format(
                            response))

    def test_get_org_iam_policies_raises_error(self):
        """Test get_org_iam_policies() raises ApiExecutionError on error."""
        self.mock_http_response(fake_crm_responses.GET_PROJECT_NOT_FOUND, '403')

        with self.assertRaises(api_errors.ApiExecutionError):
            self.crm_api_client.get_org_iam_policies('foo', self.project_id)

    def test_get_folder(self):
        """Test get_folder()."""
        self.mock_http_response(fake_crm_responses.GET_FOLDER)
        folder_id = fake_crm_responses.FAKE_FOLDER_ID

        response = self.crm_api_client.get_folder(folder_id)
        self.assertEqual('folders/{}'.format(folder_id),
                         response.get('name'))

    def test_get_folder_raises_error(self):
        """Test get_folder() raises ApiExecutionError when HTTP error occurs."""
        self.mock_http_response(fake_crm_responses.GET_PROJECT_NOT_FOUND, '403')

        with self.assertRaises(api_errors.ApiExecutionError):
            self.crm_api_client.get_folder(fake_crm_responses.FAKE_FOLDER_ID)

    def test_get_folders_all(self):
        """Test get_folders()."""
        fake_folders_response = json.dumps(
            fake_folders.FAKE_FOLDERS_API_RESPONSE1)
        expected_folders = fake_folders.EXPECTED_FAKE_FOLDERS1
        self.mock_http_response(fake_folders_response)

        result = list(self.crm_api_client.get_folders('folders'))
        self.assertEquals(expected_folders, result)

    def test_get_folders_active(self):
        """Test get_folders() only for lifecycle_state=ACTIVE."""

        fake_folders_response = json.dumps(
            fake_folders.FAKE_ACTIVE_FOLDERS_API_RESPONSE1)
        expected_folders = fake_folders.EXPECTED_FAKE_ACTIVE_FOLDERS1

        self.mock_http_response(fake_folders_response)

        result = list(self.crm_api_client.get_folders(
            'folders', lifecycle_state='ACTIVE'))
        self.assertEquals(expected_folders, result)

    def test_get_folders_raises_error(self):
        """Test get_folders() raises ApiExecutionError on HTTP error."""
        self.mock_http_response(fake_crm_responses.GET_PROJECT_NOT_FOUND, '403')

        with self.assertRaises(api_errors.ApiExecutionError):
            list(self.crm_api_client.get_folders('folders'))

    def test_get_folder_iam_policies(self):
        """Test get folder IAM policies."""
        self.mock_http_response(fake_crm_responses.GET_IAM_POLICY)
        folder_id = fake_crm_responses.FAKE_FOLDER_ID

        response = self.crm_api_client.get_folder_iam_policies('foo', folder_id)

        self.assertTrue('bindings' in response.get('iam_policy', {}),
                        msg='Response {} does not contain "bindings".'.format(
                            response))

    def test_get_folder_iam_policies_raises_error(self):
        """Test get_folder_iam_policies() raises ApiExecutionError."""
        self.mock_http_response(fake_crm_responses.GET_PROJECT_NOT_FOUND, '403')

        with self.assertRaises(api_errors.ApiExecutionError):
            self.crm_api_client.get_folder_iam_policies(
                'foo', fake_crm_responses.FAKE_FOLDER_ID)


if __name__ == '__main__':
    unittest.main()
