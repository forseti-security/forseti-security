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

from googleapiclient.errors import HttpError
from httplib2 import HttpLib2Error
from ratelimiter import RateLimiter

from google.cloud.security.common.gcp_api._base_client import _BaseClient
from google.cloud.security.common.gcp_api._base_client import ApiExecutionError
from google.cloud.security.common.util.log_util import LogUtil


LOGGER = LogUtil.setup_logging(__name__)


class CloudResourceManagerClient(_BaseClient):
    """Resource Manager Client."""

    API_NAME = 'cloudresourcemanager'
    DEFAULT_MAX_QUERIES = 400

    def __init__(self, credentials=None, rate_limiter=None):
        super(CloudResourceManagerClient, self).__init__(
            credentials=credentials, api_name=self.API_NAME)
        if rate_limiter:
            self.rate_limiter = rate_limiter
        else:
            self.rate_limiter = RateLimiter(self.DEFAULT_MAX_QUERIES, 100)


    def get_project(self, project_id):
        """Get all the projects from organization.

        Args:
            project_id: The string project id.

        Returns:
            The project response object.

        Raises:
            ApiExecutionError: An error has occurred when executing the API.
        """
        projects_stub = self.service.projects()

        try:
            with self.rate_limiter:
                request = projects_stub.get(projectId=project_id)
                response = self._execute(request)
                return response
        except (HttpError, HttpLib2Error) as e:
            LOGGER.error(ApiExecutionError(project_id, e))
        return None

    def get_projects(self, resource_name, organization_id):
        """Get all the projects from organization.

        Args:
            resource_name: String of the resource's name.
            organization_id: String of the organization id
                in Google Cloud Platform

        Yields:
            An iterable of resource manager project list response.
            https://cloud.google.com/resource-manager/reference/rest/v1/projects/list#response-body

        Raises:
            ApiExecutionError: An error has occurred when executing the API.
        """
        projects_stub = self.service.projects()
        # TODO: The filter may break once folders are implemented.
        # pylint: disable=redefined-builtin
        # TODO: Stop redefining a built-in to remove pylint disable.
        filter = 'parent.type:organization parent.id:%s' % organization_id
        request = projects_stub.list(filter=filter)

        try:
            with self.rate_limiter:
                while request is not None:
                    response = self._execute(request)
                    yield response
                    request = projects_stub.list_next(
                        previous_request=request,
                        previous_response=response)
        except (HttpError, HttpLib2Error) as e:
            raise ApiExecutionError(resource_name, e)

    def get_project_iam_policies(self, resource_name, project_number):
        """Get all the iam policies of given project numbers.

        Args:
            resource_name: String of the resource's name.
            project_number: Integer of project number.

        Returns:
            Per-project dictionary of iam policies.
            Example: {project_number: policy}
            https://cloud.google.com/resource-manager/reference/rest/Shared.Types/Policy
        """
        projects_stub = self.service.projects()

        try:
            with self.rate_limiter:
                request = projects_stub.getIamPolicy(
                    resource=project_number, body={})
                response = self._execute(request)
                return {'project_number': project_number,
                        'iam_policy': response}
        except (HttpError, HttpLib2Error) as e:
            raise ApiExecutionError(resource_name, e)

    def get_organization(self, org_name):
        """Get organizations.

        Args:
            org_name: The string org name with format "organizations/$ORG_ID"

        Returns:
            The org response object if found, otherwise False.

        Raises:
            ApiExecutionError: An error has occurred when executing the API.
        """
        orgs_stub = self.service.organizations()

        try:
            with self.rate_limiter:
                request = orgs_stub.get(name=org_name)
                response = self._execute(request)
                return response
        except (HttpError, HttpLib2Error) as e:
            LOGGER.error(ApiExecutionError(org_name, e))
        return None

    def get_org_iam_policies(self, resource_name, org_id):
        """Get all the iam policies of an org.

        Args:
            resource_name: String of the resource's name.
            org_id: Integer of the org id.

        Yields:
            An iterable of iam policies as per-org dictionary.
            Example: {org_id: org_id,
                      iam_policy: iam_policy}
            https://cloud.google.com/resource-manager/reference/rest/Shared.Types/Policy

        Raises:
            ApiExecutionError: An error has occurred when executing the API.
        """
        orgs_stub = self.service.organizations()
        resource_id = 'organizations/' + str(org_id)

        try:
            with self.rate_limiter:
                request = orgs_stub.getIamPolicy(
                    resource=resource_id, body={})
                response = self._execute(request)
                yield {'org_id': org_id,
                       'iam_policy': response}
        except (HttpError, HttpLib2Error) as e:
            raise ApiExecutionError(resource_name, e)
