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

import mock

from googleapiclient.errors import HttpError
from httplib2 import HttpLib2Error

from google.apputils import basetest
from google.cloud.security.common.gcp_api import _base_client
from google.cloud.security.common.gcp_api import _supported_apis
from google.cloud.security.common.gcp_api import cloud_resource_manager as crm
from google.cloud.security.common.gcp_api import errors as api_errors
from google.cloud.security.common.gcp_type.resource import LifecycleState
from google.cloud.security.common.util import log_util


class CloudResourceManagerTest(basetest.TestCase):
    """Test the Cloud Resource Manager API Client."""

    MAX_CRM_API_CALLS_PER_100_SECONDS = 88888

    @mock.patch.object(crm, 'FLAGS')
    @mock.patch.object(_base_client.BaseClient, '__init__', autospec=True)
    def setUp(self, mock_base_client, mock_flags):
        """Set up."""

        mock_flags.max_crm_api_calls_per_100_seconds = (
            self.MAX_CRM_API_CALLS_PER_100_SECONDS)
        self.crm_api_client = crm.CloudResourceManagerClient()

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

        mock_project_stub = mock.MagicMock()
        self.crm_api_client.service = mock.MagicMock()
        self.crm_api_client.service.projects.return_value = mock_project_stub

        project_id = '11111'
        self.crm_api_client.get_project(project_id)
        self.crm_api_client.service.projects.assert_called_once_with()
        mock_project_stub.get.assert_called_once_with(projectId=project_id)

        # test the error handling
        crm.LOGGER = mock.MagicMock()
        self.crm_api_client._execute = mock.MagicMock()
        self.crm_api_client._execute.side_effect = HttpLib2Error

        self.crm_api_client.get_project(project_id)
        self.assertEquals(1, crm.LOGGER.error.call_count)

    def test_get_projects(self):
        """Test get projects."""

        mock_project_stub = mock.MagicMock()
        mock_project_stub.list_next.return_value = None
        self.crm_api_client.service = mock.MagicMock()
        self.crm_api_client.service.projects.return_value = mock_project_stub
        
        fake_projects = {
            'projects': [
                {
                    'name': 'project1',
                    'projectId': 'project1',
                    'projectNumber': '25621943694',
                    'lifecycleState': 'ACTIVE',
                },
                {
                    'name': 'project2',
                    'projectId': 'project2',
                    'projectNumber': '94226340476',
                    'lifecycleState': 'DELETE_REQUESTED',
                },
                {
                    'name': 'project3',
                    'projectId': 'project3',
                    'projectNumber': '133851422272',
                    'lifecycleState': 'ACTIVE',
                }]
            }

        expected_projects = [{
            'projects': [
                {
                    'name': 'project1',
                    'projectId': 'project1',
                    'projectNumber': '25621943694',
                    'lifecycleState': 'ACTIVE',
                },
                {
                    'name': 'project3',
                    'projectId': 'project3',
                    'projectNumber': '133851422272',
                    'lifecycleState': 'ACTIVE',
                }]
            }]

        self.crm_api_client._execute = mock.MagicMock(
            return_value=fake_projects)
        
        org_id = '11111'
        result = list(self.crm_api_client.get_projects(
            'foo', org_id, lifecycleState=LifecycleState.ACTIVE))
        self.assertEquals(expected_projects[0], result[0])


    def test_get_project_iam_policies(self):
        """Test get project IAM policies."""

        self.crm_api_client = crm.CloudResourceManagerClient()
        mock_project_stub = mock.MagicMock()
        self.crm_api_client.service = mock.MagicMock()
        self.crm_api_client.service.projects.return_value = mock_project_stub

        project_id = '11111'
        self.crm_api_client.get_project_iam_policies('foo', project_id)
        self.crm_api_client.service.projects.assert_called_once_with()
        mock_project_stub.getIamPolicy.assert_called_once_with(
            resource=project_id, body={})

        # test the error handling
        self.crm_api_client._execute = mock.MagicMock()
        self.crm_api_client._execute.side_effect = HttpLib2Error

        with self.assertRaises(api_errors.ApiExecutionError):
            self.crm_api_client.get_project_iam_policies('foo', project_id)

    def test_get_organization(self):
        """Test get organizations."""

        self.crm_api_client = crm.CloudResourceManagerClient()
        mock_orgs_stub = mock.MagicMock()
        self.crm_api_client.service = mock.MagicMock()
        self.crm_api_client.service.organizations.return_value = mock_orgs_stub

        org_name = 'foo'
        self.crm_api_client.get_organization(org_name)
        self.crm_api_client.service.organizations.assert_called_once_with()
        mock_orgs_stub.get.assert_called_once_with(name=org_name)

        # test the error handling
        crm.LOGGER = mock.MagicMock()
        self.crm_api_client._execute = mock.MagicMock()
        self.crm_api_client._execute.side_effect = HttpLib2Error

        self.crm_api_client.get_organization(org_name)
        self.assertEquals(1, crm.LOGGER.error.call_count)

    def test_get_org_iam_policies(self):
        """Test get org IAM policies."""

        self.crm_api_client = crm.CloudResourceManagerClient()
        mock_orgs_stub = mock.MagicMock()
        self.crm_api_client.service = mock.MagicMock()
        self.crm_api_client.service.organizations.return_value = mock_orgs_stub

        org_id = '11111'
        response = '22222'
        expected_result = {'org_id': org_id, 'iam_policy': response}
        self.crm_api_client._execute = mock.MagicMock(return_value=response)
        result = self.crm_api_client.get_org_iam_policies('foo', org_id)

        self.assertEquals(expected_result, next(result))
        self.crm_api_client.service.organizations.assert_called_once_with()
        mock_orgs_stub.getIamPolicy.assert_called_once_with(
            resource='organizations/11111', body={})

        # test the error handling
        self.crm_api_client._execute = mock.MagicMock()
        self.crm_api_client._execute.side_effect = HttpLib2Error

        with self.assertRaises(api_errors.ApiExecutionError):
            self.crm_api_client.get_project_iam_policies('foo', org_id)


if __name__ == '__main__':
    basetest.main()
