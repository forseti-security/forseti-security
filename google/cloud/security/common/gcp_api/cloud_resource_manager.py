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

from google.cloud.security.common.gcp_api import _base_repository
from google.cloud.security.common.gcp_api import errors as api_errors
from google.cloud.security.common.util import log_util


LOGGER = log_util.get_logger(__name__)


class CloudResourceManagerRepository(_base_repository.BaseRepositoryClient):
    """Cloud Resource Manager Respository."""

    def __init__(self,
                 quota_max_calls=None,
                 quota_period=100.0,
                 use_rate_limiter=True):
        """Constructor.

        Args:
          quota_max_calls (int): Allowed requests per <quota_period> for the
              API.
          quota_period (float): The time period to limit the quota_requests to.
          use_rate_limiter (bool): Set to false to disable the use of a rate
              limiter for this service.
        """
        if not quota_max_calls:
            use_rate_limiter = False

        self._projects = None
        self._organizations = None
        self._folders = None

        super(CloudResourceManagerRepository, self).__init__(
            'cloudresourcemanager', versions=['v1', 'v2'],
            quota_max_calls=quota_max_calls,
            quota_period=quota_period,
            use_rate_limiter=use_rate_limiter)

    @property
    def projects(self):
        """A _ResourceManagerProjectsRepository instance.

        Returns:
          object: A _ResourceManagerProjectsRepository instance.
        """
        if not self._projects:
            self._projects = self._init_repository(
                _ResourceManagerProjectsRepository,
                self.gcp_services['v1'],
                self._projects)

        return self._projects

    @property
    def organizations(self):
        """A _ResourceManagerOrganizationsRepository instance.

        Returns:
          object: A _ResourceManagerOrganizationsRepository instance.
        """
        if not self._organizations:
            self._organizations = self._init_repository(
                _ResourceManagerOrganizationsRepository,
                self.gcp_services['v1'],
                self._organizations)

        return self._organizations

    @property
    def folders(self):
        """A _ResourceManagerFoldersRepository instance.

        Returns:
          object: A _ResourceManagerFoldersRepository instance.
        """
        if not self._folders:
            self._folders = self._init_repository(
                _ResourceManagerFoldersRepository,
                self.gcp_services['v2'],
                self._folders)

        return self._folders


class _ResourceManagerProjectsRepository(
        _base_repository.GCPRepository,
        _base_repository.GetIamPolicyQueryMixin):
    """Implementation of Cloud Resource Manager Projects repository."""

    def __init__(self, gcp_service, credentials, rate_limiter):
        """Constructor.

        Args:
          gcp_service (object): A GCE service object built using the Google
              discovery API.
          credentials (object): GoogleCredentials.
          rate_limiter (object): A rate limiter instance.
        """
        super(_ResourceManagerProjectsRepository, self).__init__(
            gcp_service=gcp_service,
            credentials=credentials,
            component='projects',
            entity='',
            rate_limiter=rate_limiter)

    def get(self, project, fields=None):
        """Get the project resource data.

        Args:
          project (str): The project id or number to query.
          fields (str): Fields to include in the response - partial response.

        Returns:
          dict: Response from the API.
        """
        return self.execute_query(
            verb='get',
            verb_arguments={'projectId': project, 'fields': fields}
        )

    def get_ancestry(self, project, fields=None):
        """Get the project ancestory data.

        Args:
          project (str): The project id or number to query.
          fields (str): Fields to include in the response - partial response.

        Returns:
          dict: Response from the API.
        """
        return self.execute_query(
            verb='getAncestry',
            verb_arguments={'projectId': project, 'fields': fields, 'body': {}}
        )

    def list(self, parent_id=None, parent_type=None, filters=None, fields=None):
        """List projects, optionally by parent.

        Args:
          parent_id (str): The id of the organization or folder parent object.
          parent_type (str): Either folder or organization.
          filters (str): Additional filters to apply to the restrict the
              set of projects returned.
          fields (str): Fields to include in the response - partial response.

        Yields:
          dict: Response from the API.
        """
        if not filters:
            filters = []
        if parent_id:
            filters.append('parent.id:{}'.format(parent_id))
        if parent_type:
            filters.append('parent.type:{}'.format(parent_type))

        for resp in self.execute_paged_query(
                verb='list',
                verb_arguments={'filter': ' '.join(filters), 'fields': fields}):
            yield resp


class _ResourceManagerOrganizationsRepository(
        _base_repository.GCPRepository,
        _base_repository.GetIamPolicyQueryMixin):
    """Implementation of Cloud Resource Manager Organizations repository."""

    def __init__(self, gcp_service, credentials, rate_limiter):
        """Constructor.

        Args:
          gcp_service (object): A GCE service object built using the Google
              discovery API.
          credentials (object): GoogleCredentials.
          rate_limiter (object): A rate limiter instance.
        """
        super(_ResourceManagerOrganizationsRepository, self).__init__(
            gcp_service=gcp_service,
            credentials=credentials,
            component='organizations',
            entity='',
            rate_limiter=rate_limiter)

    def get(self, organization_id, fields=None):
        """Get the organization resource data.

        Args:
          organization_id (str): The organization id to query, either just the
              id or the id prefixed with 'organizations/'.
          fields (str): Fields to include in the response - partial response.

        Returns:
          dict: Response from the API.
        """
        if not organization_id.startswith('organizations/'):
            organization_id = 'organizations/{}'.format(organization_id)
        return self.execute_query(
            verb='get',
            verb_arguments={'name': organization_id, 'fields': fields}
        )

    # pylint: disable=redefined-builtin
    def search(self, filter=None, fields=None):
        """Get all organizations the caller has access to.

        Args:
          filter (str): Additional filters to apply to the restrict the
              set of organizations returned.
          fields (str): Fields to include in the response - partial response.

        Yields:
          dict: Response from the API.
        """
        req_body = {}
        if filter:
            req_body['filter'] = filter
        for resp in self.execute_search_query(
                verb='search',
                verb_arguments={'body': req_body, 'fields': fields}):
            yield resp
    # pylint: enable=redefined-builtin


class _ResourceManagerFoldersRepository(
        _base_repository.GCPRepository,
        _base_repository.GetIamPolicyQueryMixin):
    """Implementation of Cloud Resource Manager Folders repository."""

    def __init__(self, gcp_service, credentials, rate_limiter):
        """Constructor.

        Args:
          gcp_service (object): A GCE service object built using the Google
              discovery API.
          credentials (object): GoogleCredentials.
          rate_limiter (object): A rate limiter instance.
        """
        super(_ResourceManagerFoldersRepository, self).__init__(
            gcp_service=gcp_service,
            credentials=credentials,
            component='folders',
            entity='',
            rate_limiter=rate_limiter)

    def get(self, folder_id, fields=None):
        """Get the project resource data.

        Args:
          folder_id (str): The folder id to query, optionally prefixed with
              'folders/'.
          fields (str): Fields to include in the response - partial response.

        Returns:
          dict: Response from the API.
        """
        if not folder_id.startswith('folders/'):
            folder_id = 'folders/{}'.format(folder_id)
        return self.execute_query(
            verb='get',
            verb_arguments={'name': folder_id, 'fields': fields}
        )

    def list(self, parent, fields=None):
        """List folders under a parent resource.

        Args:
          parent (str): The organization id or folder id to list children of,
              they must be prefixed with 'organizations/' or 'folders/'.
          fields (str): Fields to include in the response - partial response.

        Yields:
          dict: Response from the API.
        """
        for resp in self.execute_paged_query(
                verb='list',
                verb_arguments={'parent': parent, 'fields': fields}):
            yield resp

    def search(self, query=None, fields=None):
        """Get all folders the caller has access to based on query.

        Args:
          query (str): Additional filters to apply to the restrict the
              set of folders returned.
          fields (str): Fields to include in the response - partial response.

        Yields:
          dict: Response from the API.
        """
        req_body = {}
        if query:
            req_body['query'] = query
        for resp in self.execute_search_query(
                verb='search',
                verb_arguments={'body': req_body, 'fields': fields}):
            yield resp


class CloudResourceManagerClient(object):
    """Resource Manager Client."""

    DEFAULT_QUOTA_TIMESPAN_PER_SECONDS = 100  # pylint: disable=invalid-name

    def __init__(self, global_configs, **kwargs):
        """Initialize.

        Args:
            global_configs (dict): Forseti config.
            **kwargs (dict): The kwargs.
        """
        del kwargs
        max_calls = global_configs.get('max_crm_api_calls_per_100_seconds')
        self.repository = CloudResourceManagerRepository(
            quota_max_calls=max_calls,
            quota_period=self.DEFAULT_QUOTA_TIMESPAN_PER_SECONDS,
            use_rate_limiter=True)

    def get_project(self, project_id):
        """Get all the projects from organization.

        Args:
            project_id (str): The project id (not project number).

        Returns:
            dict: The project response object.

        Raises:
            ApiExecutionError: An error has occurred when executing the API.
        """
        try:
            return self.repository.projects.get(project_id)
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
        filters = []

        for key, value in filterargs.items():
            filters.append('{}:{}'.format(key, value))

        try:
            for response in self.repository.projects.list(filters=filters):
                yield response
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
        try:
            return self.repository.projects.get_iam_policy(project_identifier)
        except (errors.HttpError, HttpLib2Error) as e:
            raise api_errors.ApiExecutionError(resource_name, e)

    def get_organization(self, org_name):
        """Get organization by org_name.

        Args:
            org_name (str): The org name with format "organizations/$ORG_ID"

        Returns:
            dict: The org response object if found, otherwise False.
        """
        try:
            return self.repository.organizations.get(org_name)
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
        try:
            for response in self.repository.organizations.search():
                yield response
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
        resource_id = 'organizations/%s' % org_id
        try:
            iam_policy = (
                self.repository.organizations.get_iam_policy(resource_id))
            return {'org_id': org_id,
                    'iam_policy': iam_policy}
        except (errors.HttpError, HttpLib2Error) as e:
            raise api_errors.ApiExecutionError(resource_name, e)

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
        try:
            return self.repository.folders.get(folder_name)
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
        queries = []
        if 'lifecycle_state' in kwargs:
            queries.append('lifecycleState={}'.format(
                kwargs.get('lifecycle_state')))

        try:
            for response in self.repository.folders.search(
                    query=' '.join(queries)):
                yield response
        except (errors.HttpError, HttpLib2Error) as e:
            raise api_errors.ApiExecutionError(resource_name, e)

    def get_folder_iam_policies(self, resource_name, folder_id):
        """Get all the iam policies of an folder.

        Args:
            resource_name (str): The resource name (type).
            folder_id (int): The folder id.

        Returns:
            dict: Folder IAM policy for given folder_id.

        Raises:
            ApiExecutionError: An error has occurred when executing the API.
        """
        resource_id = 'folders/%s' % folder_id
        try:
            iam_policy = self.repository.folders.get_iam_policy(resource_id)
            return {'folder_id': folder_id,
                    'iam_policy': iam_policy}
        except (errors.HttpError, HttpLib2Error) as e:
            raise api_errors.ApiExecutionError(resource_name, e)
