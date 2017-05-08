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

"""Tests the Bigquery client."""


from googleapiclient.errors import HttpError
from httplib2 import HttpLib2Error
import mock

from google.apputils import basetest
from google.cloud.security.common.gcp_api import _base_client
from google.cloud.security.common.gcp_api import _supported_apis
from google.cloud.security.common.gcp_api import bigquery as bq
from google.cloud.security.common.gcp_api import errors as api_errors
from google.cloud.security.common.util import log_util


class BigqueryTestCase(basetest.TestCase):
    """Test the Bigquery API Client."""

    MAX_BIGQUERY_API_CALLS_PER_100_SECONDS = 88888

    @mock.patch.object(bq, 'FLAGS')
    @mock.patch.object(_base_client.BaseClient, '__init__', autospec=True)
    def setUp(self, mock_base_client, mock_flags):
        """Set up."""

        mock_flags.max_bigquery_api_calls_per_100_seconds = (
            self.MAX_BIGQUERY_API_CALLS_PER_100_SECONDS)
        self.bq_api_client = bq.BigQueryClient()

    def test_api_client_is_initialized(self):
        """Test that the api client is initialized."""

        self.assertEquals(
            self.MAX_BIGQUERY_API_CALLS_PER_100_SECONDS,
            self.bq_api_client.rate_limiter.max_calls)
        self.assertEquals(
            bq.BigQueryClient.DEFAULT_QUOTA_TIMESPAN_PER_SECONDS,
            self.bq_api_client.rate_limiter.period)

    def test_get_project(self):
        """Test can get project."""

        mock_project_stub = mock.MagicMock()
        self.bq_api_client.service = mock.MagicMock()
        self.bq_api_client.service.projects.return_value = mock_project_stub

        project_id = '11111'
        self.bq_api_client.get_project(project_id)
        self.bq_api_client.service.projects.assert_called_once_with()
        mock_project_stub.get.assert_called_once_with(projectId=project_id)

        # test the error handling
        bq.LOGGER = mock.MagicMock()
        self.bq_api_client._execute = mock.MagicMock()
        self.bq_api_client._execute.side_effect = HttpLib2Error

        self.bq_api_client.get_project(project_id)
        self.assertEquals(1, bq.LOGGER.error.call_count)

    def test_get_projects(self):
        """Test get projects."""

        mock_project_stub = mock.MagicMock()
        mock_project_stub.list_next.return_value = None
        self.bq_api_client.service = mock.MagicMock()
        self.bq_api_client.service.projects.return_value = mock_project_stub

        fake_projects = {

            }

        expected_projects = [{

            }]

        self.bq_api_client._execute = mock.MagicMock(
            return_value=fake_projects)

        org_id = '11111'
        result = list(self.bq_api_client.get_projects(
            'foo'))
        self.assertEquals(expected_projects[0], result[0])


    def test_get_project_iam_policies(self):
        """Test get project IAM policies."""

        mock_project_stub = mock.MagicMock()
        self.bq_api_client.service = mock.MagicMock()
        self.bq_api_client.service.projects.return_value = mock_project_stub

        project_id = '11111'
        self.bq_api_client.get_project_iam_policies('foo', project_id)
        self.bq_api_client.service.projects.assert_called_once_with()
        mock_project_stub.getIamPolicy.assert_called_once_with(
            resource=project_id, body={})

        # test the error handling
        self.bq_api_client._execute = mock.MagicMock()
        self.bq_api_client._execute.side_effect = HttpLib2Error

        with self.assertRaises(api_errors.ApiExecutionError):
            self.bq_api_client.get_project_iam_policies('foo', project_id)

    def test_get_organization(self):
        """Test get organizations."""

        mock_orgs_stub = mock.MagicMock()
        self.bq_api_client.service = mock.MagicMock()
        self.bq_api_client.service.organizations.return_value = mock_orgs_stub

        org_name = 'foo'
        self.bq_api_client.get_organization(org_name)
        self.bq_api_client.service.organizations.assert_called_once_with()
        mock_orgs_stub.get.assert_called_once_with(name=org_name)

        # test the error handling
        bq.LOGGER = mock.MagicMock()
        self.bq_api_client._execute = mock.MagicMock()
        self.bq_api_client._execute.side_effect = HttpLib2Error

        self.bq_api_client.get_organization(org_name)
        self.assertEquals(1, bq.LOGGER.error.call_count)

    def test_get_organizations(self):
        """Test get organizations."""

        mock_orgs_stub = mock.MagicMock()
        self.bq_api_client.service = mock.MagicMock()
        self.bq_api_client.service.organizations.return_value = mock_orgs_stub

        fake_orgs_response = fake_orgs.FAKE_ORGS_RESPONSE
        expected_orgs = fake_orgs.EXPECTED_FAKE_ORGS_FROM_API

        self.bq_api_client._execute = mock.MagicMock(
            return_value=fake_orgs_response)

        result = list(self.bq_api_client.get_organizations('organizations'))
        self.assertEquals(expected_orgs, [fake_orgs_response])

    def test_get_org_iam_policies(self):
        """Test get org IAM policies."""

        mock_orgs_stub = mock.MagicMock()
        self.bq_api_client.service = mock.MagicMock()
        self.bq_api_client.service.organizations.return_value = mock_orgs_stub

        org_id = '11111'
        response = '22222'
        expected_result = {'org_id': org_id, 'iam_policy': response}
        self.bq_api_client._execute = mock.MagicMock(return_value=response)
        result = self.bq_api_client.get_org_iam_policies('foo', org_id)

        self.assertEquals(expected_result, result)
        self.bq_api_client.service.organizations.assert_called_once_with()
        mock_orgs_stub.getIamPolicy.assert_called_once_with(
            resource='organizations/11111', body={})

        # test the error handling
        self.bq_api_client._execute = mock.MagicMock()
        self.bq_api_client._execute.side_effect = HttpLib2Error

        with self.assertRaises(api_errors.ApiExecutionError):
            self.bq_api_client.get_project_iam_policies('foo', org_id)


if __name__ == '__main__':
    basetest.main()
