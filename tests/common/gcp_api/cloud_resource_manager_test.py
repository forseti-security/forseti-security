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

"""Tests the Cloud Resource Manager API client."""
import json
import unittest
import mock
import google.auth
from google.oauth2 import credentials

from tests import unittest_utils
from tests.common.gcp_api.test_data import fake_crm_responses
from tests.common.gcp_api.test_data import http_mocks
from google.cloud.forseti.common.gcp_api import cloud_resource_manager as crm
from google.cloud.forseti.common.gcp_api import errors as api_errors
from google.cloud.forseti.common.gcp_type.resource import LifecycleState


class CloudResourceManagerTest(unittest_utils.ForsetiTestCase):
    """Test the Cloud Resource Manager API Client."""

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

    @mock.patch.object(
        google.auth, 'default',
        return_value=(mock.Mock(spec_set=credentials.Credentials),
                      'test-project'))
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
        response = json.dumps(
            fake_crm_responses.FAKE_ACTIVE_PROJECTS_API_RESPONSE)
        http_mocks.mock_http_response(response)

        result = list(self.crm_api_client.get_projects(
            parent_id=fake_crm_responses.FAKE_ORG_ID,
            parent_type='organization',
            lifecycleState=LifecycleState.ACTIVE))
        self.assertEquals(
            fake_crm_responses.EXPECTED_FAKE_ACTIVE_PROJECTS1, result)

    def test_get_projects_all(self):
        """Test get_projects() for all lifecycle_states."""
        response = json.dumps(fake_crm_responses.FAKE_PROJECTS_API_RESPONSE1)
        http_mocks.mock_http_response(response)

        result = list(self.crm_api_client.get_projects())
        self.assertEquals(fake_crm_responses.EXPECTED_FAKE_PROJECTS1, result)

    def test_get_projects_api_error(self):
        """Test get_projects() raises ApiExecutionError on HTTP error."""
        http_mocks.mock_http_response(fake_crm_responses.GET_PROJECT_NOT_FOUND,
                                      '403')

        with self.assertRaises(api_errors.ApiExecutionError):
            list(self.crm_api_client.get_projects())

    def test_get_project_ancestry(self):
        """Validate get_project_ancestry() with test project."""
        http_mocks.mock_http_response(
            fake_crm_responses.GET_PROJECT_ANCESTRY_RESPONSE)
        result = self.crm_api_client.get_project_ancestry(
            fake_crm_responses.FAKE_PROJECT_ID)
        self.assertEquals(fake_crm_responses.EXPECTED_PROJECT_ANCESTRY_IDS,
                          [r['resourceId']['id'] for r in result])

    def test_get_project_ancestry_api_error(self):
        """Test get_projects() raises ApiExecutionError on HTTP error."""
        http_mocks.mock_http_response(fake_crm_responses.GET_PROJECT_NOT_FOUND,
                                      '403')

        with self.assertRaises(api_errors.ApiExecutionError):
            self.crm_api_client.get_project_ancestry(
                fake_crm_responses.FAKE_PROJECT_ID)

    def test_get_project_iam_policies(self):
        """Test get project IAM policies."""
        http_mocks.mock_http_response(fake_crm_responses.GET_IAM_POLICY)

        response = self.crm_api_client.get_project_iam_policies(self.project_id)
        self.assertTrue('bindings' in response)

    def test_get_project_iam_policies_errors(self):
        """Test the error handling."""
        http_mocks.mock_http_response(fake_crm_responses.GET_PROJECT_NOT_FOUND,
                                      '403')

        with self.assertRaises(api_errors.ApiExecutionError):
            self.crm_api_client.get_project_iam_policies(self.project_id)

    def test_get_project_org_policies(self):
        """Test get project org policies."""
        http_mocks.mock_http_response(fake_crm_responses.LIST_ORG_POLICIES)

        response = self.crm_api_client.get_project_org_policies(self.project_id)
        self.assertEqual([fake_crm_responses.TEST_ORG_POLICY_CONSTRAINT],
                         [r['constraint'] for r in response])

    def test_get_project_org_policies_errors(self):
        """Test the error handling."""
        http_mocks.mock_http_response(fake_crm_responses.GET_PROJECT_NOT_FOUND,
                                      '403')

        with self.assertRaises(api_errors.ApiExecutionError):
            self.crm_api_client.get_project_org_policies(self.project_id)

    def test_get_organization(self):
        """Test get single organization."""
        http_mocks.mock_http_response(fake_crm_responses.GET_ORGANIZATION)
        org_id = fake_crm_responses.FAKE_ORG_ID

        response = self.crm_api_client.get_organization(org_id)
        self.assertEqual('organizations/{}'.format(org_id),
                         response.get('name'))

    def test_get_organization_raises_error(self):
        """Test get_organization() raises ApiExecutionError on HTTP error."""
        http_mocks.mock_http_response(fake_crm_responses.GET_PROJECT_NOT_FOUND,
                                      '403')

        with self.assertRaises(api_errors.ApiExecutionError):
            self.crm_api_client.get_organization(fake_crm_responses.FAKE_ORG_ID)

    def test_get_organizations(self):
        """Test get organizations."""
        fake_orgs_response = json.dumps(fake_crm_responses.FAKE_ORGS_RESPONSE)
        http_mocks.mock_http_response(fake_orgs_response)
        expected_orgs = fake_crm_responses.EXPECTED_FAKE_ORGS_FROM_API

        result = self.crm_api_client.get_organizations()
        self.assertEquals(expected_orgs, result)

    def test_get_organizations_multiple_pages(self):
        """Test multiple pages when calling get_organizations()."""
        mock_responses = []
        for page in fake_crm_responses.SEARCH_ORGANIZATIONS:
            mock_responses.append(({'status': '200'}, page))
        http_mocks.mock_http_response_sequence(mock_responses)

        results = self.crm_api_client.get_organizations()
        self.assertEquals(fake_crm_responses.EXPECTED_ORGANIZATIONS_FROM_SEARCH,
                          [r.get('name') for r in results])

    def test_get_organizations_raises_error(self):
        """Test get_organizations() raises ApiExecutionError on HTTP error."""
        http_mocks.mock_http_response(fake_crm_responses.GET_PROJECT_NOT_FOUND,
                                      '403')

        with self.assertRaises(api_errors.ApiExecutionError):
            list(self.crm_api_client.get_organizations())

    def test_get_org_iam_policies(self):
        """Test get org IAM policies."""
        http_mocks.mock_http_response(fake_crm_responses.GET_IAM_POLICY)
        org_id = fake_crm_responses.FAKE_ORG_ID

        response = self.crm_api_client.get_org_iam_policies(org_id)

        self.assertTrue('bindings' in response,
                        msg='Response {} does not contain "bindings".'.format(
                            response))

    def test_get_org_iam_policies_raises_error(self):
        """Test get_org_iam_policies() raises ApiExecutionError on error."""
        http_mocks.mock_http_response(fake_crm_responses.GET_PROJECT_NOT_FOUND,
                                      '403')
        org_id = fake_crm_responses.FAKE_ORG_ID

        with self.assertRaises(api_errors.ApiExecutionError):
            self.crm_api_client.get_org_iam_policies(org_id)

    def test_get_org_org_policies(self):
        """Test get org org policies."""
        http_mocks.mock_http_response(fake_crm_responses.LIST_ORG_POLICIES)
        org_id = fake_crm_responses.FAKE_ORG_ID

        response = self.crm_api_client.get_org_org_policies(org_id)
        self.assertEqual([fake_crm_responses.TEST_ORG_POLICY_CONSTRAINT],
                         [r['constraint'] for r in response])

    def test_get_org_org_policies_errors(self):
        """Test the error handling."""
        http_mocks.mock_http_response(fake_crm_responses.GET_PROJECT_NOT_FOUND,
                                      '403')
        org_id = fake_crm_responses.FAKE_ORG_ID

        with self.assertRaises(api_errors.ApiExecutionError):
            self.crm_api_client.get_org_org_policies(org_id)

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
            fake_crm_responses.FAKE_FOLDERS_API_RESPONSE1)
        http_mocks.mock_http_response(fake_folders_response)
        expected_folders = fake_crm_responses.EXPECTED_FAKE_FOLDERS1

        result = self.crm_api_client.get_folders(show_deleted=True)
        self.assertEquals(expected_folders, result)

    def test_get_folders_parent(self):
        """Test get_folders()."""
        fake_folders_response = json.dumps(
            fake_crm_responses.FAKE_FOLDERS_LIST_API_RESPONSE1)
        http_mocks.mock_http_response(fake_folders_response)
        expected_folders = fake_crm_responses.EXPECTED_FAKE_FOLDERS_LIST1
        parent = 'organizations/9999'

        result = self.crm_api_client.get_folders(parent=parent)
        self.assertEquals(expected_folders, result)

    def test_get_folders_active(self):
        """Test get_folders() only for lifecycle_state=ACTIVE."""

        fake_folders_response = json.dumps(
            fake_crm_responses.FAKE_ACTIVE_FOLDERS_API_RESPONSE1)
        http_mocks.mock_http_response(fake_folders_response)

        expected_folders = fake_crm_responses.EXPECTED_FAKE_ACTIVE_FOLDERS1

        result = self.crm_api_client.get_folders(show_deleted=False)
        self.assertEquals(expected_folders, result)

    def test_get_folders_raises_error(self):
        """Test get_folders() raises ApiExecutionError on HTTP error."""
        http_mocks.mock_http_response(fake_crm_responses.GET_PROJECT_NOT_FOUND,
                                      '403')

        with self.assertRaises(api_errors.ApiExecutionError):
            self.crm_api_client.get_folders()

        with self.assertRaises(api_errors.ApiExecutionError):
            self.crm_api_client.get_folders(parent='folders/111')

    def test_get_folder_iam_policies(self):
        """Test get folder IAM policies."""
        http_mocks.mock_http_response(fake_crm_responses.GET_IAM_POLICY)
        folder_id = fake_crm_responses.FAKE_FOLDER_ID

        response = self.crm_api_client.get_folder_iam_policies(folder_id)

        self.assertTrue('bindings' in response,
                        msg='Response {} does not contain "bindings".'.format(
                            response))

    def test_get_folder_iam_policies_raises_error(self):
        """Test get_folder_iam_policies() raises ApiExecutionError."""
        http_mocks.mock_http_response(fake_crm_responses.GET_PROJECT_NOT_FOUND,
                                      '403')

        with self.assertRaises(api_errors.ApiExecutionError):
            self.crm_api_client.get_folder_iam_policies(
                fake_crm_responses.FAKE_FOLDER_ID)

    def test_get_folder_org_policies(self):
        """Test get folder org policies."""
        http_mocks.mock_http_response(fake_crm_responses.LIST_ORG_POLICIES)
        folder_id = fake_crm_responses.FAKE_FOLDER_ID

        response = self.crm_api_client.get_folder_org_policies(folder_id)
        self.assertEqual([fake_crm_responses.TEST_ORG_POLICY_CONSTRAINT],
                         [r['constraint'] for r in response])

    def test_get_folder_org_policies_errors(self):
        """Test the error handling."""
        http_mocks.mock_http_response(fake_crm_responses.GET_PROJECT_NOT_FOUND,
                                      '403')
        folder_id = fake_crm_responses.FAKE_FOLDER_ID

        with self.assertRaises(api_errors.ApiExecutionError):
            self.crm_api_client.get_folder_org_policies(folder_id)

    def test_get_org_policy(self):
        """Test get_org_policy for org, folder and project."""
        test_cases = [
            (
                'folders/{}'.format(fake_crm_responses.FAKE_FOLDER_ID),
                False,
                fake_crm_responses.GET_ORG_POLICY_NO_POLICY
            ),
            (
                'folders/{}'.format(fake_crm_responses.FAKE_FOLDER_ID),
                True,
                fake_crm_responses.GET_EFFECTIVE_ORG_POLICY
            ),
            (
                'projects/{}'.format(fake_crm_responses.FAKE_PROJECT_ID),
                False,
                fake_crm_responses.GET_ORG_POLICY_NO_POLICY
            ),
            (
                'projects/{}'.format(fake_crm_responses.FAKE_PROJECT_ID),
                True,
                fake_crm_responses.GET_EFFECTIVE_ORG_POLICY
            ),
            (
                'organizations/{}'.format(fake_crm_responses.FAKE_ORG_ID),
                False,
                fake_crm_responses.GET_ORG_POLICY_NO_POLICY
            ),
            (
                'organizations/{}'.format(fake_crm_responses.FAKE_ORG_ID),
                True,
                fake_crm_responses.GET_EFFECTIVE_ORG_POLICY
            ),
        ]
        for (resource_id, effective_policy, fake_response) in test_cases:
            http_mocks.mock_http_response(fake_response)
            response = self.crm_api_client.get_org_policy(
                resource_id,
                fake_crm_responses.TEST_ORG_POLICY_CONSTRAINT,
                effective_policy=effective_policy)
            self.assertEqual(fake_crm_responses.TEST_ORG_POLICY_CONSTRAINT,
                             response['constraint'])

    def test_get_org_policy_errors(self):
        """Test get_org_policy for error handling."""
        test_cases = [
            (
                'folders/{}'.format(fake_crm_responses.FAKE_FOLDER_ID),
                fake_crm_responses.GET_PROJECT_NOT_FOUND,
                api_errors.ApiExecutionError
            ),
            (
                'projects/{}'.format(fake_crm_responses.FAKE_PROJECT_ID),
                fake_crm_responses.GET_PROJECT_NOT_FOUND,
                api_errors.ApiExecutionError
            ),
            (
                'organizations/{}'.format(fake_crm_responses.FAKE_ORG_ID),
                fake_crm_responses.GET_PROJECT_NOT_FOUND,
                api_errors.ApiExecutionError
            ),
            (
                'bad_resource_id',
                None,
                ValueError
            ),
        ]
        for (resource_id, response, expected_exception) in test_cases:
            if response:
                http_mocks.mock_http_response(response, '403')
            with self.assertRaises(expected_exception):
                self.crm_api_client.get_org_policy(
                    resource_id,
                    fake_crm_responses.TEST_ORG_POLICY_CONSTRAINT)

    def test_get_liens(self):
        """Test get liens."""
        http_mocks.mock_http_response(fake_crm_responses.GET_LIENS)
        response = self.crm_api_client.get_project_liens(
            fake_crm_responses.FAKE_PROJECT_ID)
        self.assertEqual(response, fake_crm_responses.EXPECTED_LIENS)


if __name__ == '__main__':
    unittest.main()
