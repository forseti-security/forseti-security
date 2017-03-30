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
from google.cloud.security.common.gcp_type.resource import LifecycleState
from google.cloud.security.common.util import log_util

LOGGER = log_util.get_logger(__name__)

DEFAULT_MAX_QUERIES = 100
DEFAULT_RATE_BUCKET_SECONDS = 100


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
            self.rate_limiter = self.get_rate_limiter()

    @staticmethod
    def get_rate_limiter():
        """Return an appriopriate rate limiter."""
        return RateLimiter(
            DEFAULT_MAX_QUERIES,
            DEFAULT_RATE_BUCKET_SECONDS)

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

    def get_projects(self, resource_name, organization_id, **filterargs):
        """Get all the projects from organization.

        Args:
            resource_name: String of the resource's name.
            organization_id: String of the organization id
                in Google Cloud Platform.
            filterargs: Extra project filter args.

        Yields:
            An iterable of resource manager project list response.
            https://cloud.google.com/resource-manager/reference/rest/v1/projects/list#response-body

        Raises:
            ApiExecutionError: An error has occurred when executing the API.
        """
        projects_stub = self.service.projects()
        # TODO: The filter currently does not get projects under folders.
        project_filter = [
            'parent.type:organization',
            'parent.id:%s' % organization_id,
        ]
        lifecycle_state = filterargs.get('lifecycleState')
        if lifecycle_state:
            project_filter.append('lifecycleState:%s' % lifecycle_state)

        for filter_key in filterargs:
            project_filter.append('%s:%s' %
                                  (filter_key, filterargs[filter_key]))
        request = projects_stub.list(filter=' '.join(project_filter))

        try:
            with self.rate_limiter:
                while request is not None:
                    response = self._execute(request)

                    # TODO: once CRM API allows for direct filtering on
                    # lifecycleState, add it to the project_filter list
                    # and don't manually filter here.
                    if lifecycle_state == LifecycleState.ACTIVE:
                        yield {
                            'projects': [
                                p for p in response.get('projects')
                                if (p.get('lifecycleState') ==
                                    LifecycleState.ACTIVE)
                            ]
                        }

                    request = projects_stub.list_next(
                        previous_request=request,
                        previous_response=response)
        except (HttpError, HttpLib2Error) as e:
            raise ApiExecutionError(resource_name, e)

    def get_project_iam_policies(self, resource_name, project_identifier):
        """Get all the iam policies of given project numbers.

        Args:
            resource_name: String of the resource's name.
            project_identifier: Either the project number or the project id.

        Returns:
            IAM policies of the project.
            https://cloud.google.com/resource-manager/reference/rest/Shared.Types/Policy
        """
        projects_stub = self.service.projects()

        try:
            with self.rate_limiter:
                request = projects_stub.getIamPolicy(
                    resource=project_identifier, body={})
                return self._execute(request)
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
            Example: {org_id: org_id, iam_policy: iam_policy}
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
