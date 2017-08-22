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

"""Wrapper for Resource Manager API client."""

from googleapiclient import errors
from httplib2 import HttpLib2Error
from ratelimiter import RateLimiter

from google.cloud.security.common.gcp_api import _base_client
from google.cloud.security.common.gcp_api import errors as api_errors
from google.cloud.security.common.util import log_util


LOGGER = log_util.get_logger(__name__)


class CloudResourceManagerClient(_base_client.BaseClient):
    """Resource Manager Client."""

    API_NAME = 'cloudresourcemanager'
    DEFAULT_QUOTA_TIMESPAN_PER_SECONDS = 100  # pylint: disable=invalid-name

    def __init__(self, global_configs, **kwargs):
        """Initialize.

        Args:
            global_configs (dict): Forseti config.
            **kwargs (dict): The kwargs.
        """
        super(CloudResourceManagerClient, self).__init__(
            global_configs, api_name=self.API_NAME, **kwargs)
        self.service_v2 = self.get_service(self.API_NAME, 'v2')

        # TODO: we will need multiple rate limiters when we need to invoke
        # the CRM write API for enforcement.
        self.rate_limiter = RateLimiter(
            self.global_configs.get('max_crm_api_calls_per_100_seconds'),
            self.DEFAULT_QUOTA_TIMESPAN_PER_SECONDS)

    def get_project(self, project_id):
        """Get all the projects from organization.

        Args:
            project_id (str): The project id (not project number).

        Returns:
            dict: The project response object.

        Raises:
            ApiExecutionError: An error has occurred when executing the API.
        """
        projects_api = self.service.projects()

        try:
            request = projects_api.get(projectId=project_id)
            response = self._execute(request, self.rate_limiter)
            return response
        except (errors.HttpError, HttpLib2Error) as e:
            raise api_errors.ApiExecutionError(project_id, e)

    def get_projects(self, resource_name, **filterargs):
        """Get all the projects this application has access to.

        Args:
            resource_name (str): The resource type.
            filterargs (dict): Extra project filter args.

        Yields:
            dict: The projects.list() response.
            https://cloud.google.com/resource-manager/reference/rest/v1/projects/list#response-body

        Raises:
            ApiExecutionError: An error has occurred when executing the API.
        """
        projects_api = self.service.projects()
        project_filter = []

        for filter_key in filterargs:
            project_filter.append('%s:%s' %
                                  (filter_key, filterargs[filter_key]))
        request = projects_api.list(filter=' '.join(project_filter))

        # TODO: Convert this over to _base_client._build_paged_result().
        try:
            while request is not None:
                response = self._execute(request, self.rate_limiter)
                yield response

                request = projects_api.list_next(
                    previous_request=request,
                    previous_response=response)
        except (errors.HttpError, HttpLib2Error) as e:
            raise api_errors.ApiExecutionError(resource_name, e)

    def get_project_iam_policies(self, resource_name, project_identifier):
        """Get all the iam policies of given project numbers.

        Args:
            resource_name (str): The resource type.
            project_identifier (str): Either the project number or the
                project id.

        Returns:
            list: IAM policies of the project.
            https://cloud.google.com/resource-manager/reference/rest/Shared.Types/Policy
        """
        projects_api = self.service.projects()

        try:
            request = projects_api.getIamPolicy(
                resource=project_identifier, body={})
            return self._execute(request, self.rate_limiter)
        except (errors.HttpError, HttpLib2Error) as e:
            raise api_errors.ApiExecutionError(resource_name, e)

    def get_organization(self, org_name):
        """Get organization by org_name.

        Args:
            org_name (str): The org name with format "organizations/$ORG_ID"

        Returns:
            dict: The org response object if found, otherwise False.
        """
        organizations_api = self.service.organizations()

        try:
            request = organizations_api.get(name=org_name)
            response = self._execute(request, self.rate_limiter)
            return response
        except (errors.HttpError, HttpLib2Error) as e:
            raise api_errors.ApiExecutionError(org_name, e)

    def get_organizations(self, resource_name):
        """Get organizations that this application has access to.

        Args:
            resource_name (str): The resource type.

        Yields:
            dict: An iterator of the response from the organizations API,
                which is paginated and contains a list of organizations.
        """
        organizations_api = self.service.organizations()
        next_page_token = None

        try:
            while True:
                req_body = {}
                if next_page_token:
                    req_body['pageToken'] = next_page_token
                request = organizations_api.search(body=req_body)
                response = self._execute(request, self.rate_limiter)
                yield response
                next_page_token = response.get('nextPageToken')
                if not next_page_token:
                    break
        except (errors.HttpError, HttpLib2Error) as e:
            raise api_errors.ApiExecutionError(resource_name, e)

    def get_org_iam_policies(self, resource_name, org_id):
        """Get all the iam policies of an org.

        Args:
            resource_name (str): The resource type.
            org_id (int): The org id number.

        Returns:
            dict: Organization IAM policy for given org_id.
            https://cloud.google.com/resource-manager/reference/rest/Shared.Types/Policy

        Raises:
            ApiExecutionError: An error has occurred when executing the API.
        """
        organizations_api = self.service.organizations()
        try:
            request = organizations_api.getIamPolicy(
                resource=org_id, body={})
            return self._execute(request, self.rate_limiter)
        except (errors.HttpError, HttpLib2Error) as e:
            raise api_errors.ApiExecutionError(resource_name, e)

    def get_org_org_policies(self, org_id):
        """Get all the organization policies of an org.

        Args:
            org_id (int): The org id number.

        Returns:
            dict: Organization org policy for given org_id.

        Raises:
            ApiExecutionError: An error has occurred when executing the API.
        """
        organizations_api = self.service.organizations()
        try:
            request = organizations_api.getOrgPolicy(
                resource=org_id, body={})
            return self._execute(request, self.rate_limiter)
        except (errors.HttpError, HttpLib2Error) as e:
            raise api_errors.ApiExecutionError(org_id, e)

    def get_folder(self, folder_name):
        """Get a folder.

        Args:
            folder_name (str): The unique folder name, with the format
                "folders/{folderId}".

        Returns:
            dict: The folder API response.

        Raises:
            ApiExecutionError: An error has occurred when executing the API.
        """
        folders_api = self.service.folders()

        try:
            request = folders_api.get(name=folder_name)
            response = self._execute(request, self.rate_limiter)
            return response
        except (errors.HttpError, HttpLib2Error) as e:
            raise api_errors.ApiExecutionError(folder_name, e)

    def get_folders(self, resource_name, **kwargs):
        """Find all folders Forseti can access.

        Args:
            resource_name (str): The resource type.
            **kwargs (dict): Extra args.

        Yields:
            dict: The folders API response.

        Raises:
            ApiExecutionError: An error has occurred when executing the API.
        """
        folders_api = self.service_v2.folders()
        next_page_token = None
        lifecycle_state_filter = kwargs.get('lifecycle_state')

        try:
            while True:
                req_body = {}
                if next_page_token:
                    req_body['pageToken'] = next_page_token
                if lifecycle_state_filter:
                    req_body['lifecycleState'] = lifecycle_state_filter
                request = folders_api.search(body=req_body)
                response = self._execute(request, self.rate_limiter)
                yield response
                next_page_token = response.get('nextPageToken')
                if not next_page_token:
                    break
        except (errors.HttpError, HttpLib2Error) as e:
            raise api_errors.ApiExecutionError(resource_name, e)

    def get_folder_iam_policies(self, folder_id):
        """Get all the iam policies of an folder.

        Args:
            folder_id (int): The folder id.

        Returns:
            dict: Folder IAM policy for given folder_id.

        Raises:
            ApiExecutionError: An error has occurred when executing the API.
        """
        folders_api = self.service_v2.folders()
        resource_id = folder_id
        try:
            request = folders_api.getIamPolicy(
                resource=resource_id, body={})
            return {'folder_id': folder_id,
                    'iam_policy': self._execute(request, self.rate_limiter)}
        except (errors.HttpError, HttpLib2Error) as e:
            raise api_errors.ApiExecutionError('folder', e)
