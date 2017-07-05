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

"""Tests the Storage client."""


from googleapiclient.errors import HttpError
from httplib2 import HttpLib2Error
import mock

from tests.unittest_utils import ForsetiTestCase
from google.cloud.security.common.gcp_api import _base_client
from google.cloud.security.common.gcp_api import _supported_apis
from google.cloud.security.common.gcp_api import cloud_resource_manager as crm
from google.cloud.security.common.gcp_api import errors as api_errors
from google.cloud.security.common.gcp_type.resource import LifecycleState
from google.cloud.security.common.util import log_util
from tests.common.gcp_type.test_data import fake_folders
from tests.common.gcp_type.test_data import fake_orgs
from tests.common.gcp_type.test_data import fake_projects


class CloudResourceManagerTest(ForsetiTestCase):
    """Test the Cloud Resource Manager API Client."""

    MAX_CRM_API_CALLS_PER_100_SECONDS = 88888

    @mock.patch('google.cloud.security.common.gcp_api._base_client.discovery')
    @mock.patch('google.cloud.security.common.gcp_api._base_client.GoogleCredentials')
    def setUp(self, mock_google_credential, mock_discovery):
        """Set up."""

        fake_global_configs = {
            'max_crm_api_calls_per_100_seconds':
                self.MAX_CRM_API_CALLS_PER_100_SECONDS}
        self.crm_api_client = crm.CloudResourceManagerClient(
            global_configs=fake_global_configs)

        self.crm_api_client.service = mock.MagicMock()
        self.crm_api_client.service.projects = mock.MagicMock()
        self.crm_api_client.service.organizations = mock.MagicMock()

        self.fake_projects_api_response1 = \
            fake_projects.FAKE_PROJECTS_API_RESPONSE1
        self.expected_fake_projects1 = fake_projects.EXPECTED_FAKE_PROJECTS1
        self.expected_fake_active_projects1 = \
            fake_projects.EXPECTED_FAKE_ACTIVE_PROJECTS1

    def test_api_client_is_initialized(self):
        """Test that the api client is initialized."""

        self.assertEquals(
            self.MAX_CRM_API_CALLS_PER_100_SECONDS,
            self.crm_api_client.rate_limiter.max_calls)
        self.assertEquals(
            crm.CloudResourceManagerClient.DEFAULT_QUOTA_TIMESPAN_PER_SECONDS,
            self.crm_api_client.rate_limiter.period)

    def test_get_project(self):
        """Test can get project."""

        mock_get = mock.MagicMock()
        self.crm_api_client.service.projects.return_value.get = mock_get

        project_id = '11111'
        self.crm_api_client.get_project(project_id)
        self.crm_api_client.service.projects.assert_called_once_with()
        mock_get.assert_called_once_with(projectId=project_id)

        # test the error handling
        crm.LOGGER = mock.MagicMock()
        self.crm_api_client._execute = mock.MagicMock()
        self.crm_api_client._execute.side_effect = HttpLib2Error

        with self.assertRaises(api_errors.ApiExecutionError):
            self.crm_api_client.get_project(project_id)

    def test_get_projects_active(self):
        """Test get_projects() for ACTIVE projects."""

        self.crm_api_client.service \
            .projects.return_value.list_next.return_value = None

        self.crm_api_client._execute = mock.MagicMock(
            return_value=fake_projects.FAKE_ACTIVE_PROJECTS_API_RESPONSE)

        result = list(self.crm_api_client.get_projects(
            'projects', lifecycleState=LifecycleState.ACTIVE))
        self.assertEquals(self.expected_fake_active_projects1, result)

    def test_get_projects_all(self):
        """Test get_projects() for all lifecycle_states."""

        self.crm_api_client.service \
            .projects.return_value.list_next.return_value = None

        self.crm_api_client._execute = mock.MagicMock(
            return_value=self.fake_projects_api_response1)

        result = list(self.crm_api_client.get_projects('projects'))
        self.assertEquals(self.expected_fake_projects1, result)

    def test_get_projects_api_error(self):
        """Test get_projects() raises ApiExecutionError on HTTP error."""

        self.crm_api_client._execute = mock.MagicMock(
            side_effect=HttpLib2Error)

        with self.assertRaises(api_errors.ApiExecutionError):
            list(self.crm_api_client.get_projects('projects'))

    def test_get_project_iam_policies(self):
        """Test get project IAM policies."""

        mock_get_iam_policy = mock.MagicMock()
        self.crm_api_client.service \
            .projects.return_value.getIamPolicy = mock_get_iam_policy

        project_id = '11111'
        self.crm_api_client.get_project_iam_policies('foo', project_id)
        self.crm_api_client.service.projects.assert_called_once_with()
        mock_get_iam_policy.assert_called_once_with(resource=project_id, body={})

        # test the error handling
        self.crm_api_client._execute = mock.MagicMock(side_effect=HttpLib2Error)

        with self.assertRaises(api_errors.ApiExecutionError):
            self.crm_api_client.get_project_iam_policies('foo', project_id)

    def test_get_organization(self):
        """Test get single organization."""

        mock_get = mock.MagicMock()
        self.crm_api_client.service.organizations.return_value.get = mock_get

        org_name = 'foo'
        self.crm_api_client.get_organization(org_name)
        self.crm_api_client.service.organizations.assert_called_once_with()
        mock_get.assert_called_once_with(name=org_name)

    def test_get_organization_raises_error(self):
        """Test get_organization() raises ApiExecutionError on HTTP error."""

        org_name = 'foo'

        self.crm_api_client._execute = mock.MagicMock(side_effect=HttpLib2Error)

        with self.assertRaises(api_errors.ApiExecutionError):
            self.crm_api_client.get_organization(org_name)

    def test_get_organizations(self):
        """Test get organizations."""

        fake_orgs_response = fake_orgs.FAKE_ORGS_RESPONSE
        expected_orgs = fake_orgs.EXPECTED_FAKE_ORGS_FROM_API

        self.crm_api_client._execute = mock.MagicMock(
            return_value=fake_orgs_response)

        result = list(self.crm_api_client.get_organizations('organizations'))
        self.assertEquals(expected_orgs, result)

    def test_get_organizations_raises_error(self):
        """Test get_organizations() raises ApiExecutionError on HTTP error."""

        self.crm_api_client._execute = mock.MagicMock(
            side_effect=HttpLib2Error)

        with self.assertRaises(api_errors.ApiExecutionError):
            list(self.crm_api_client.get_organizations('organizations'))

    def test_get_org_iam_policies(self):
        """Test get org IAM policies."""

        mock_get_iam_policy = mock.MagicMock()
        self.crm_api_client.service \
            .organizations.return_value.getIamPolicy = mock_get_iam_policy

        org_id = '11111'
        response = '22222'
        expected_result = {'org_id': org_id, 'iam_policy': response}
        self.crm_api_client._execute = mock.MagicMock(return_value=response)
        result = self.crm_api_client.get_org_iam_policies(
            'organizations', org_id)

        self.assertEquals(expected_result, result)
        self.crm_api_client.service.organizations.assert_called_once_with()
        mock_get_iam_policy.assert_called_once_with(
            resource='organizations/11111', body={})

    def test_get_org_iam_policies_raises_error(self):
        """Test get_org_iam_policies() raises ApiExecutionError on HTTP error."""

        org_id = '11111'
        response = '22222'
        expected_result = {'org_id': org_id, 'iam_policy': response}

        self.crm_api_client._execute = mock.MagicMock()
        self.crm_api_client._execute.side_effect = HttpLib2Error

        with self.assertRaises(api_errors.ApiExecutionError):
            self.crm_api_client.get_project_iam_policies(
                'organizations', org_id)

    def test_get_folder(self):
        """Test get_folder()."""

        mock_get = mock.MagicMock()
        self.crm_api_client.service.folders.return_value.get = mock_get

        folder_name = '11111'
        self.crm_api_client.get_folder(folder_name)
        self.crm_api_client.service.folders.assert_called_once_with()
        mock_get.assert_called_once_with(name=folder_name)

    def test_get_folder_raises_error(self):
        """Test get_folder() raises ApiExecutionError when HTTP error occurs."""

        mock_get = mock.MagicMock()
        self.crm_api_client.service.folders.return_value.get = mock_get

        crm.LOGGER = mock.MagicMock()
        self.crm_api_client._execute = mock.MagicMock(side_effect=HttpLib2Error)

        with self.assertRaises(api_errors.ApiExecutionError):
            self.crm_api_client.get_folder('foo')

    def test_get_folders_all(self):
        """Test get_folders()."""

        fake_folders_response = fake_folders.FAKE_FOLDERS_API_RESPONSE1
        expected_folders = fake_folders.EXPECTED_FAKE_FOLDERS1

        self.crm_api_client._execute = mock.MagicMock(
            return_value=fake_folders_response)

        result = list(self.crm_api_client.get_folders('folders'))
        self.assertEquals(expected_folders, result)

    def test_get_folders_active(self):
        """Test get_folders() only for lifecycle_state=ACTIVE."""

        fake_folders_response = {
            'folders': [
                fake_folders.FAKE_FOLDERS_API_RESPONSE1['folders'][0],
                fake_folders.FAKE_FOLDERS_API_RESPONSE1['folders'][2],
            ]
        }
        expected_folders = fake_folders.EXPECTED_FAKE_ACTIVE_FOLDERS1

        self.crm_api_client._execute = mock.MagicMock(
            return_value=fake_folders_response)

        result = list(self.crm_api_client.get_folders(
            'folders', lifecycle_state='ACTIVE'))
        self.assertEquals(expected_folders, result)

    def test_get_folders_raises_error(self):
        """Test get_folders() raises ApiExecutionError on HTTP error."""

        self.crm_api_client._execute = mock.MagicMock(
            side_effect=HttpLib2Error)

        with self.assertRaises(api_errors.ApiExecutionError):
            list(self.crm_api_client.get_folders('folders'))


if __name__ == '__main__':
    unittest.main()
