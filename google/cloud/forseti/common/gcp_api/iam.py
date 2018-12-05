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

"""Wrapper for IAM API client."""
from googleapiclient import errors
from httplib2 import HttpLib2Error

from google.cloud.forseti.common.gcp_api import _base_repository
from google.cloud.forseti.common.gcp_api import api_helpers
from google.cloud.forseti.common.gcp_api import errors as api_errors
from google.cloud.forseti.common.gcp_api import repository_mixins
from google.cloud.forseti.common.util import logger

LOGGER = logger.get_logger(__name__)
API_NAME = 'iam'


class IamRepositoryClient(_base_repository.BaseRepositoryClient):
    """IAM API Respository."""

    def __init__(self,
                 quota_max_calls=None,
                 quota_period=1.0,
                 use_rate_limiter=True):
        """Constructor.

        Args:
            quota_max_calls (int): Allowed requests per <quota_period> for the
                API.
            quota_period (float): The time period to limit the requests within.
            use_rate_limiter (bool): Set to false to disable the use of a rate
                limiter for this service.
        """
        if not quota_max_calls:
            use_rate_limiter = False

        self._organizations_roles = None
        self._projects_roles = None
        self._projects_serviceaccounts = None
        self._projects_serviceaccounts_keys = None
        self._roles = None

        super(IamRepositoryClient, self).__init__(
            API_NAME, versions=['v1'],
            quota_max_calls=quota_max_calls,
            quota_period=quota_period,
            use_rate_limiter=use_rate_limiter)

    # Turn off docstrings for properties.
    # pylint: disable=missing-return-doc, missing-return-type-doc
    @property
    def organizations_roles(self):
        """An _IamOrganizationsRolesRepository instance."""
        if not self._organizations_roles:
            self._organizations_roles = self._init_repository(
                _IamOrganizationsRolesRepository)
        return self._organizations_roles

    @property
    def projects_roles(self):
        """An _IamProjectsRolesRepository instance."""
        if not self._projects_roles:
            self._projects_roles = self._init_repository(
                _IamProjectsRolesRepository)
        return self._projects_roles

    @property
    def projects_serviceaccounts(self):
        """An _IamProjectsServiceAccountsRepository instance."""
        if not self._projects_serviceaccounts:
            self._projects_serviceaccounts = self._init_repository(
                _IamProjectsServiceAccountsRepository)
        return self._projects_serviceaccounts

    @property
    def projects_serviceaccounts_keys(self):
        """An _IamProjectsServiceAccountsKeysRepository instance."""
        if not self._projects_serviceaccounts_keys:
            self._projects_serviceaccounts_keys = self._init_repository(
                _IamProjectsServiceAccountsKeysRepository)
        return self._projects_serviceaccounts_keys

    @property
    def roles(self):
        """An _IamRolesRepository instance."""
        if not self._roles:
            self._roles = self._init_repository(
                _IamRolesRepository)
        return self._roles
    # pylint: enable=missing-return-doc, missing-return-type-doc


class _IamOrganizationsRolesRepository(
        repository_mixins.ListQueryMixin,
        _base_repository.GCPRepository):
    """Implementation of Iam Organizations Roles repository."""

    def __init__(self, **kwargs):
        """Constructor.

        Args:
            **kwargs (dict): The args to pass into GCPRepository.__init__()
        """
        super(_IamOrganizationsRolesRepository, self).__init__(
            key_field='parent', max_results_field='pageSize',
            component='organizations.roles', **kwargs)

    @staticmethod
    def get_name(org_id):
        """Returns a formatted name field to pass in to the API.

        Args:
            org_id (str): The id of the organization to query.

        Returns:
            str: A formatted project name.
        """
        if org_id and not org_id.startswith('organizations/'):
            org_id = 'organizations/{}'.format(org_id)
        return org_id


class _IamProjectsRolesRepository(
        repository_mixins.ListQueryMixin,
        _base_repository.GCPRepository):
    """Implementation of Iam Projects Roles repository."""

    def __init__(self, **kwargs):
        """Constructor.

        Args:
            **kwargs (dict): The args to pass into GCPRepository.__init__()
        """
        super(_IamProjectsRolesRepository, self).__init__(
            key_field='parent', max_results_field='pageSize',
            component='projects.roles', **kwargs)

    @staticmethod
    def get_name(project_id):
        """Returns a formatted name field to pass in to the API.

        Args:
            project_id (str): The id of the project to query.

        Returns:
            str: A formatted project name.
        """
        if project_id and not project_id.startswith('projects/'):
            project_id = 'projects/{}'.format(project_id)
        return project_id


class _IamProjectsServiceAccountsRepository(
        repository_mixins.GetIamPolicyQueryMixin,
        repository_mixins.ListQueryMixin,
        _base_repository.GCPRepository):
    """Implementation of Iam Projects ServiceAccounts repository."""

    def __init__(self, **kwargs):
        """Constructor.

        Args:
            **kwargs (dict): The args to pass into GCPRepository.__init__()
        """
        super(_IamProjectsServiceAccountsRepository, self).__init__(
            key_field='name', max_results_field='pageSize',
            component='projects.serviceAccounts', **kwargs)

    def get_iam_policy(self, resource, fields=None, verb='getIamPolicy',
                       include_body=False, resource_field='resource', **kwargs):
        """Get Service Account IAM Policy.

        Args:
            self (GCPRespository): An instance of a GCPRespository class.
            resource (str): The id of the resource to fetch.
            fields (str): Fields to include in the response - partial response.
            verb (str): The method to call on the API.
            include_body (bool): If true, include an empty body parameter in the
                method args.
            resource_field (str): The parameter name of the resource field to
                pass to the method.
            **kwargs (dict): Optional additional arguments to pass to the query.

        Returns:
            dict: GCE response.
        """
        # The IAM getIamPolicy does not allow the 'body' argument, so this
        # overrides the default behavior by setting include_body to False.
        return repository_mixins.GetIamPolicyQueryMixin.get_iam_policy(
            self, resource, fields=fields, verb=verb, include_body=include_body,
            resource_field=resource_field, **kwargs)

    @staticmethod
    def get_name(project_id):
        """Returns a formatted name field to pass in to the API.

        Args:
            project_id (str): The id of the project to query.

        Returns:
            str: A formatted project name.
        """
        if not project_id.startswith('projects/'):
            project_id = 'projects/{}'.format(project_id)
        return project_id


class _IamProjectsServiceAccountsKeysRepository(
        repository_mixins.ListQueryMixin,
        _base_repository.GCPRepository):
    """Implementation of Iam Projects ServiceAccounts Keys repository."""

    def __init__(self, **kwargs):
        """Constructor.

        Args:
            **kwargs (dict): The args to pass into GCPRepository.__init__()
        """
        super(_IamProjectsServiceAccountsKeysRepository, self).__init__(
            key_field='name', component='projects.serviceAccounts.keys',
            **kwargs)


class _IamRolesRepository(
        repository_mixins.ListQueryMixin,
        _base_repository.GCPRepository):
    """Implementation of Iam Roles repository."""

    def __init__(self, **kwargs):
        """Constructor.

        Args:
            **kwargs (dict): The args to pass into GCPRepository.__init__()
        """
        super(_IamRolesRepository, self).__init__(
            max_results_field='pageSize', component='roles', **kwargs)


class IAMClient(object):
    """IAM Client."""

    USER_MANAGED = 'USER_MANAGED'
    SYSTEM_MANAGED = 'SYSTEM_MANAGED'
    KEY_TYPES = frozenset([USER_MANAGED, SYSTEM_MANAGED])

    def __init__(self, global_configs, **kwargs):
        """Initialize.

        Args:
            global_configs (dict): Global configurations.
            **kwargs (dict): The kwargs.
        """
        max_calls, quota_period = api_helpers.get_ratelimiter_config(
            global_configs, API_NAME)

        self.repository = IamRepositoryClient(
            quota_max_calls=max_calls,
            quota_period=quota_period,
            use_rate_limiter=kwargs.get('use_rate_limiter', True))

    def get_curated_roles(self, parent=None):
        """Get information about organization roles

        Args:
            parent (str): An optional parent ID to query. If unset, defaults
                to returning the list of curated roles in GCP.

        Returns:
            list: The response of retrieving the curated roles.

        Raises:
            ApiExecutionError: ApiExecutionError is raised if the call to the
                GCP API fails.
        """
        try:
            paged_results = self.repository.roles.list(parent=parent,
                                                       view='FULL')
            flattened_results = api_helpers.flatten_list_results(paged_results,
                                                                 'roles')
            LOGGER.debug('Getting information about organization roles,'
                         ' parent = %s, flattened_results = %s',
                         parent, flattened_results)
            return flattened_results
        except (errors.HttpError, HttpLib2Error) as e:
            api_exception = api_errors.ApiExecutionError(
                'project_roles', e, 'parent', parent)
            LOGGER.exception(api_exception)
            raise api_exception

    def get_organization_roles(self, org_id):
        """Get information about custom organization roles.

        Args:
            org_id (str): The id of the organization.

        Returns:
            list: The response of retrieving the organization roles.

        Raises:
            ApiExecutionError: ApiExecutionError is raised if the call to the
                GCP API fails.
        """
        name = self.repository.organizations_roles.get_name(org_id)

        try:
            paged_results = self.repository.organizations_roles.list(
                name, view='FULL')
            flattened_results = api_helpers.flatten_list_results(paged_results,
                                                                 'roles')
            LOGGER.debug('Getting information about custom organization roles,'
                         ' org_id = %s, flattened_results = %s',
                         org_id, flattened_results)
            return flattened_results
        except (errors.HttpError, HttpLib2Error) as e:
            api_exception = api_errors.ApiExecutionError(
                'organizations_roles', e, 'name', name)
            LOGGER.exception(api_exception)
            raise api_exception

    def get_project_roles(self, project_id):
        """Get information about custom project roles.

        Args:
            project_id (str): The id of the project.

        Returns:
            list: The response of retrieving the project roles.

        Raises:
            ApiExecutionError: ApiExecutionError is raised if the call to the
                GCP API fails.
        """
        name = self.repository.projects_roles.get_name(project_id)

        try:
            paged_results = self.repository.projects_roles.list(name,
                                                                view='FULL')
            flattened_results = api_helpers.flatten_list_results(paged_results,
                                                                 'roles')
            LOGGER.debug('Getting the information about custom project roles,'
                         ' project_id = %s, flattened_results = %s',
                         project_id, flattened_results)
            return flattened_results
        except (errors.HttpError, HttpLib2Error) as e:
            api_exception = api_errors.ApiExecutionError(
                'projects_roles', e, 'name', name)
            LOGGER.exception(api_exception)
            raise api_exception

    def get_service_accounts(self, project_id):
        """Get Service Accounts associated with a project.

        Args:
            project_id (str): The project ID to get Service Accounts for.

        Returns:
            list: List of service accounts associated with the project.

        Raises:
            ApiExecutionError: ApiExecutionError is raised if the call to the
                GCP API fails.
        """
        name = self.repository.projects_serviceaccounts.get_name(project_id)

        try:
            paged_results = self.repository.projects_serviceaccounts.list(name)
            flattened_results = api_helpers.flatten_list_results(paged_results,
                                                                 'accounts')
            LOGGER.debug('Getting service accounts associated with a project,'
                         ' project_id = %s, flattened_results = %s',
                         project_id, flattened_results)
            return flattened_results
        except (errors.HttpError, HttpLib2Error) as e:
            api_exception = api_errors.ApiExecutionError(
                'serviceAccounts', e, 'name', name)
            LOGGER.exception(api_exception)
            raise api_exception

    def get_service_account_iam_policy(self, name):
        """Get IAM policy associated with a service account.

        Args:
            name (str): The service account name to query, must be in the format
                projects/{PROJECT_ID}/serviceAccounts/{SERVICE_ACCOUNT_EMAIL}

        Returns:
            dict: The IAM policies for the service account.

        Raises:
            ApiExecutionError: ApiExecutionError is raised if the call to the
                GCP API fails.
        """
        try:
            results = self.repository.projects_serviceaccounts.get_iam_policy(
                name)
            LOGGER.debug('Getting the IAM Policy associated with the service'
                         ' account, name = %s, results = %s', name, results)
            return results
        except (errors.HttpError, HttpLib2Error) as e:
            api_exception = api_errors.ApiExecutionError(
                'serviceAccountIamPolicy', e, 'name', name)
            LOGGER.exception(api_exception)
            raise api_exception

    def get_service_account_keys(self, name, key_type=None):
        """Get keys associated with the given Service Account.

        Args:
            name (str): The service account name to query, must be in the format
                projects/{PROJECT_ID}/serviceAccounts/{SERVICE_ACCOUNT_EMAIL}
            key_type (str): Optional, the key type to include in the results.
                Can be None, USER_MANAGED or SYSTEM_MANAGED. Defaults to
                returning all key types.

        Returns:
            list: List with a dict for each key associated with the account.

        Raises:
            ValueError: Raised if an invalid key_type is specified.

            ApiExecutionError: ApiExecutionError is raised if the call to the
                GCP API fails.
        """
        try:
            kwargs = {}
            if key_type:
                if key_type not in self.KEY_TYPES:
                    raise ValueError(
                        'Key type %s is not a valid key type.' % key_type)
                kwargs['keyTypes'] = key_type
            results = self.repository.projects_serviceaccounts_keys.list(
                name, **kwargs)
            flattened_results = api_helpers.flatten_list_results(results,
                                                                 'keys')
            LOGGER.debug('Getting the keys associated with the given service'
                         ' account, name = %s, key_type = %s,'
                         ' flattened_results = %s',
                         name, key_type, flattened_results)
            return flattened_results
        except (errors.HttpError, HttpLib2Error) as e:
            api_exception = api_errors.ApiExecutionError(
                'serviceAccountKeys', e, 'name', name)
            LOGGER.exception(api_exception)
            raise api_exception
