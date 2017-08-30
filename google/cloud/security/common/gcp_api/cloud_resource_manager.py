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

"""Wrapper for Resource Manager API client."""
from googleapiclient import errors
from httplib2 import HttpLib2Error

from google.cloud.security.common.gcp_api import _base_repository
from google.cloud.security.common.gcp_api import api_helpers
from google.cloud.security.common.gcp_api import errors as api_errors
from google.cloud.security.common.gcp_api import repository_mixins
from google.cloud.security.common.util import log_util


LOGGER = log_util.get_logger(__name__)


class CloudResourceManagerRepositoryClient(
        _base_repository.BaseRepositoryClient):
    """Cloud Resource Manager Respository."""

    def __init__(self,
                 quota_max_calls=None,
                 quota_period=100.0,
                 use_rate_limiter=True):
        """Constructor.

        Args:
            quota_max_calls (int): Allowed requests per <quota_period> for the
                API.
            quota_period (float): The time period to track requests over.
            use_rate_limiter (bool): Set to false to disable the use of a rate
                limiter for this service.
        """
        if not quota_max_calls:
            use_rate_limiter = False

        self._projects = None
        self._organizations = None
        self._folders = None

        super(CloudResourceManagerRepositoryClient, self).__init__(
            'cloudresourcemanager', versions=['v1', 'v2'],
            quota_max_calls=quota_max_calls,
            quota_period=quota_period,
            use_rate_limiter=use_rate_limiter)

    # Turn off docstrings for properties.
    # pylint: disable=missing-return-doc, missing-return-type-doc
    @property
    def projects(self):
        """Returns a _ResourceManagerProjectsRepository instance."""
        if not self._projects:
            self._projects = self._init_repository(
                _ResourceManagerProjectsRepository)
        return self._projects

    @property
    def organizations(self):
        """Returns a _ResourceManagerOrganizationsRepository instance."""
        if not self._organizations:
            self._organizations = self._init_repository(
                _ResourceManagerOrganizationsRepository)
        return self._organizations

    @property
    def folders(self):
        """Returns a _ResourceManagerFoldersRepository instance."""
        if not self._folders:
            self._folders = self._init_repository(
                _ResourceManagerFoldersRepository, version='v2')
        return self._folders
    # pylint: enable=missing-return-doc, missing-return-type-doc


class _ResourceManagerProjectsRepository(
        repository_mixins.GetQueryMixin,
        repository_mixins.GetIamPolicyQueryMixin,
        repository_mixins.ListQueryMixin,
        _base_repository.GCPRepository):
    """Implementation of Cloud Resource Manager Projects repository."""

    def __init__(self, **kwargs):
        """Constructor.

        Args:
            **kwargs (dict): The args to pass into GCPRepository.__init__()
        """
        super(_ResourceManagerProjectsRepository, self).__init__(
            get_key_field='projectId', list_key_field=None,
            max_results_field='pageSize', component='projects', **kwargs)

    def get_ancestry(self, resource, **kwargs):
        """Get the project ancestory data.

        Args:
            resource (str): The project id or number to query.
            **kwargs (dict): Additional parameters to pass through to
                GetQueryMixin.get().

        Returns:
            dict: Response from the API.
        """
        return repository_mixins.GetQueryMixin.get(
            self, resource, verb='getAncestry', body=dict(), **kwargs)


class _ResourceManagerOrganizationsRepository(
        repository_mixins.GetQueryMixin,
        repository_mixins.GetIamPolicyQueryMixin,
        repository_mixins.SearchQueryMixin,
        _base_repository.GCPRepository):
    """Implementation of Cloud Resource Manager Organizations repository."""

    def __init__(self, **kwargs):
        """Constructor.

        Args:
            **kwargs (dict): The args to pass into GCPRepository.__init__()
        """
        super(_ResourceManagerOrganizationsRepository, self).__init__(
            key_field='name', max_results_field='pageSize',
            search_query_field='filter', component='organizations', **kwargs)

    @staticmethod
    def get_name(organization_id):
        """Format's an organization_id to pass in to .get().

        Args:
            organization_id (str): The organization id to query, either just the
                id or the id prefixed with 'organizations/'.

        Returns:
            str: The formatted resource name.
        """
        if not organization_id.startswith('organizations/'):
            organization_id = 'organizations/{}'.format(organization_id)
        return organization_id


class _ResourceManagerFoldersRepository(
        repository_mixins.GetQueryMixin,
        repository_mixins.GetIamPolicyQueryMixin,
        repository_mixins.ListQueryMixin,
        repository_mixins.SearchQueryMixin,
        _base_repository.GCPRepository):
    """Implementation of Cloud Resource Manager Folders repository."""

    def __init__(self, **kwargs):
        """Constructor.

        Args:
            **kwargs (dict): The args to pass into GCPRepository.__init__()
        """
        super(_ResourceManagerFoldersRepository, self).__init__(
            list_key_field='parent', get_key_field='name',
            max_results_field='pageSize', component='folders', **kwargs)

    @staticmethod
    def get_name(folder_id):
        """Format's an folder_id to pass in to .get().

        Args:
            folder_id (str): The folder id to query, either just the
                id or the id prefixed with 'folders/'.

        Returns:
            str: The formatted resource name.
        """
        if not folder_id.startswith('folders/'):
            folder_id = 'folders/{}'.format(folder_id)
        return folder_id


class CloudResourceManagerClient(object):
    """Resource Manager Client."""

    DEFAULT_QUOTA_PERIOD = 100.0

    def __init__(self, global_configs, **kwargs):
        """Initialize.

        Args:
            global_configs (dict): Forseti config.
            **kwargs (dict): The kwargs.
        """
        max_calls = global_configs.get('max_crm_api_calls_per_100_seconds')
        self.repository = CloudResourceManagerRepositoryClient(
            quota_max_calls=max_calls,
            quota_period=self.DEFAULT_QUOTA_PERIOD,
            use_rate_limiter=kwargs.get('use_rate_limiter', True))

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

    def get_projects(self, resource_name, parent_id=None, parent_type=None,
                     **filterargs):
        """Get all the projects the authenticated account has access to.

        If no parent is passed in, then all projects the caller has visibility
        to are returned. This is significantly less efficient then listing by
        parent.

        Args:
            resource_name (str): The resource type.
            parent_id (str): The id of the organization or folder parent object.
            parent_type (str): Either folder or organization.
            **filterargs (dict): Extra project filter args.

        Yields:
            dict: The projects.list() response.
            https://cloud.google.com/resource-manager/reference/rest/v1/projects/list#response-body

        Raises:
            ApiExecutionError: An error has occurred when executing the API.
        """
        filters = []

        for key, value in filterargs.items():
            filters.append('{}:{}'.format(key, value))

        if parent_id:
            filters.append('parent.id:{}'.format(parent_id))
        if parent_type:
            filters.append('parent.type:{}'.format(parent_type))

        try:
            for response in self.repository.projects.list(
                    filter=' '.join(filters)):
                yield response
        except (errors.HttpError, HttpLib2Error) as e:
            raise api_errors.ApiExecutionError(resource_name, e)

    def get_project_ancestry(self, project_id):
        """Get the full folder ancestry for a project.

        Args:
            project_id (str): Either the project number or the project id.

        Returns:
            list: The ancesters of the project, in order from direct parent to
                root organization id.
        """
        try:
            results = self.repository.projects.get_ancestry(project_id)
            return results.get('ancestor', [])
        except (errors.HttpError, HttpLib2Error) as e:
            raise api_errors.ApiExecutionError(project_id, e)

    def get_project_iam_policies(self, resource_name, project_id):
        """Get all the iam policies of given project numbers.

        Args:
            resource_name (str): The resource type.
            project_id (str): Either the project number or the project id.

        Returns:
            list: IAM policies of the project.
            https://cloud.google.com/resource-manager/reference/rest/Shared.Types/Policy
        """
        try:
            return self.repository.projects.get_iam_policy(project_id)
        except (errors.HttpError, HttpLib2Error) as e:
            raise api_errors.ApiExecutionError(resource_name, e)

    def get_organization(self, org_name):
        """Get organization by org_name.

        Args:
            org_name (str): The org name with format "organizations/$ORG_ID"

        Returns:
            dict: The org response object if found, otherwise False.
        """
        name = self.repository.organizations.get_name(org_name)
        try:
            return self.repository.organizations.get(name)
        except (errors.HttpError, HttpLib2Error) as e:
            raise api_errors.ApiExecutionError(org_name, e)

    def get_organizations(self, resource_name):
        """Get organizations that the authenticated account has access to.

        Args:
            resource_name (str): The resource type.

        Returns:
            list: A list of Folder dicts as returned by the API.
        """
        try:
            paged_results = self.repository.organizations.search()
            return api_helpers.flatten_list_results(paged_results,
                                                    'organizations')
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
        name = self.repository.folders.get_name(folder_name)
        try:
            return self.repository.folders.get(name)
        except (errors.HttpError, HttpLib2Error) as e:
            raise api_errors.ApiExecutionError(folder_name, e)

    def get_folders(self, resource_name, parent=None, show_deleted=False):
        """Find all folders that the authenticated account has access to.

        If no parent is passed in, then all folders the caller has visibility
        to are returned. This is significantly less efficient then listing by
        parent.

        Args:
            resource_name (str): The resource type.
            parent (str): Optional parent resource, either
                'organizations/{org_id}' or 'folders/{folder_id}'.
            show_deleted (bool): Determines if deleted folders should be
                returned in the results.

        Returns:
            list: A list of Folder dicts as returned by the API.

        Raises:
            ApiExecutionError: An error has occurred when executing the API.
        """
        if parent:
            paged_results = self.repository.folders.list(
                parent, showDeleted=show_deleted)
        else:
            query = ''
            if not show_deleted:
                query = 'lifecycleState=ACTIVE'
            paged_results = self.repository.folders.search(query=query)

        try:
            return api_helpers.flatten_list_results(paged_results, 'folders')
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
