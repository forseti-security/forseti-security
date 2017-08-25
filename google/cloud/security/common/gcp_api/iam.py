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

from google.cloud.security.common.gcp_api import _base_repository
from google.cloud.security.common.gcp_api import api_helpers
from google.cloud.security.common.gcp_api import errors as api_errors
from google.cloud.security.common.gcp_api import repository_mixins
from google.cloud.security.common.util import log_util

LOGGER = log_util.get_logger(__name__)


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

        self._projects_serviceaccounts = None
        self._projects_serviceaccounts_keys = None

        super(IamRepositoryClient, self).__init__(
            'iam', versions=['v1'],
            quota_max_calls=quota_max_calls,
            quota_period=quota_period,
            use_rate_limiter=use_rate_limiter)

    @property
    def projects_serviceaccounts(self):
        """An _IamProjectsServiceAccountsRepository instance.

        Returns:
            object: An _IamProjectsServiceAccountsRepository instance.
        """
        if not self._projects_serviceaccounts:
            self._projects_serviceaccounts = self._init_repository(
                _IamProjectsServiceAccountsRepository)
        return self._projects_serviceaccounts

    @property
    def projects_serviceaccounts_keys(self):
        """An _IamProjectsServiceAccountsKeysRepository instance.

        Returns:
            object: An _IamProjectsServiceAccountsKeysRepository instance.
        """
        if not self._projects_serviceaccounts_keys:
            self._projects_serviceaccounts_keys = self._init_repository(
                _IamProjectsServiceAccountsKeysRepository)
        return self._projects_serviceaccounts_keys


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


class IAMClient(object):
    """IAM Client."""

    DEFAULT_QUOTA_PERIOD = 1.0

    def __init__(self, global_configs, **kwargs):
        """Initialize.

        Args:
            global_configs (dict): Global configurations.
            **kwargs (dict): The kwargs.
        """
        max_calls = global_configs.get('max_iam_api_calls_per_second')
        self.repository = IamRepositoryClient(
            quota_max_calls=max_calls,
            quota_period=self.DEFAULT_QUOTA_PERIOD,
            use_rate_limiter=kwargs.get('use_rate_limiter', True))

    def get_service_accounts(self, project_id):
        """Get Service Accounts associated with a project.

        Args:
            project_id (str): The project ID to get Service Accounts for.

        Returns:
            list: List of service accounts associated with the project.
        """
        name = self.repository.projects_serviceaccounts.get_name(project_id)

        try:
            paged_results = self.repository.projects_serviceaccounts.list(name)
            return api_helpers.flatten_list_results(paged_results, 'accounts')
        except (errors.HttpError, HttpLib2Error) as e:
            LOGGER.warn(api_errors.ApiExecutionError(name, e))
            raise api_errors.ApiExecutionError('serviceAccounts', e)

    def get_service_account_iam_policy(self, name):
        """Get IAM policy associated with a service account.

        Args:
            name (str): The service account name to query, must be in the format
                projects/{PROJECT_ID}/serviceAccounts/{SERVICE_ACCOUNT_EMAIL}

        Returns:
            dict: The IAM policies for the service account.
        """
        try:
            return self.repository.projects_serviceaccounts.get_iam_policy(name)
        except (errors.HttpError, HttpLib2Error) as e:
            LOGGER.warn(api_errors.ApiExecutionError(name, e))
            raise api_errors.ApiExecutionError('serviceAccountIamPolicy', e)

    def get_service_account_keys(self, name):
        """Get keys associated with the given Service Account.

        Args:
            name (str): The service account name to query, must be in the format
                projects/{PROJECT_ID}/serviceAccounts/{SERVICE_ACCOUNT_EMAIL}

        Returns:
            list: List with a dict for each key associated with the account.
        """
        try:
            results = self.repository.projects_serviceaccounts_keys.list(name)
            return api_helpers.flatten_list_results(results, 'keys')
        except (errors.HttpError, HttpLib2Error) as e:
            LOGGER.warn(api_errors.ApiExecutionError(name, e))
            raise api_errors.ApiExecutionError('serviceAccountKeys', e)
