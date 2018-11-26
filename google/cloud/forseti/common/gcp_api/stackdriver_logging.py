# Copyright 2018 The Forseti Security Authors. All rights reserved.
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

"""Wrapper for Stackdriver Logging API client."""
from googleapiclient import errors
from httplib2 import HttpLib2Error

from google.cloud.forseti.common.gcp_api import _base_repository
from google.cloud.forseti.common.gcp_api import api_helpers
from google.cloud.forseti.common.gcp_api import errors as api_errors
from google.cloud.forseti.common.gcp_api import repository_mixins
from google.cloud.forseti.common.util import logger

LOGGER = logger.get_logger(__name__)
API_NAME = 'logging'


class StackdriverLoggingRepositoryClient(_base_repository.BaseRepositoryClient):
    """Stackdriver Logging API Respository."""

    def __init__(self,
                 quota_max_calls=None,
                 quota_period=1.0,
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

        self._organizations_sinks = None
        self._folders_sinks = None
        self._billing_accounts_sinks = None
        self._projects_sinks = None

        super(StackdriverLoggingRepositoryClient, self).__init__(
            API_NAME, versions=['v2'],
            quota_max_calls=quota_max_calls,
            quota_period=quota_period,
            use_rate_limiter=use_rate_limiter)

    # Turn off docstrings for properties.
    # pylint: disable=missing-return-doc, missing-return-type-doc
    @property
    def organizations_sinks(self):
        """Returns a _LoggingOrganizationsSinksRepository instance."""
        if not self._organizations_sinks:
            self._organizations_sinks = self._init_repository(
                _LoggingOrganizationsSinksRepository)
        return self._organizations_sinks

    @property
    def folders_sinks(self):
        """Returns a _LoggingFoldersSinksRepository instance."""
        if not self._folders_sinks:
            self._folders_sinks = self._init_repository(
                _LoggingFoldersSinksRepository)
        return self._folders_sinks

    @property
    def billing_accounts_sinks(self):
        """Returns a _LoggingBillingAccountsSinksRepository instance."""
        if not self._billing_accounts_sinks:
            self._billing_accounts_sinks = self._init_repository(
                _LoggingBillingAccountsSinksRepository)
        return self._billing_accounts_sinks

    @property
    def projects_sinks(self):
        """Returns a _LoggingProjectsSinksRepository instance."""
        if not self._projects_sinks:
            self._projects_sinks = self._init_repository(
                _LoggingProjectsSinksRepository)
        return self._projects_sinks
    # pylint: enable=missing-return-doc, missing-return-type-doc


class _LoggingOrganizationsSinksRepository(
        repository_mixins.ListQueryMixin,
        _base_repository.GCPRepository):
    """Implementation of Logging Organizations Sinks repository."""

    def __init__(self, **kwargs):
        """Constructor.

        Args:
            **kwargs (dict): The args to pass into GCPRepository.__init__()
        """
        super(_LoggingOrganizationsSinksRepository, self).__init__(
            key_field='parent', max_results_field='pageSize',
            component='organizations.sinks', **kwargs)

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


class _LoggingFoldersSinksRepository(
        repository_mixins.ListQueryMixin,
        _base_repository.GCPRepository):
    """Implementation of Logging Folders Sinks repository."""

    def __init__(self, **kwargs):
        """Constructor.

        Args:
            **kwargs (dict): The args to pass into GCPRepository.__init__()
        """
        super(_LoggingFoldersSinksRepository, self).__init__(
            key_field='parent', max_results_field='pageSize',
            component='folders.sinks', **kwargs)

    @staticmethod
    def get_name(folder_id):
        """Returns a formatted name field to pass in to the API.
        Args:
            folder_id (str): The id of the folder to query.
        Returns:
            str: A formatted project name.
        """
        if folder_id and not folder_id.startswith('folders/'):
            folder_id = 'folders/{}'.format(folder_id)
        return folder_id


class _LoggingBillingAccountsSinksRepository(
        repository_mixins.ListQueryMixin,
        _base_repository.GCPRepository):
    """Implementation of Logging BillingAccounts Sinks repository."""

    def __init__(self, **kwargs):
        """Constructor.

        Args:
            **kwargs (dict): The args to pass into GCPRepository.__init__()
        """
        super(_LoggingBillingAccountsSinksRepository, self).__init__(
            key_field='parent', max_results_field='pageSize',
            component='billingAccounts.sinks', **kwargs)

    @staticmethod
    def get_name(account_id):
        """Returns a formatted name field to pass in to the API.
        Args:
            account_id (str): The id of the billing account to query.
        Returns:
            str: A formatted project name.
        """
        if account_id and not account_id.startswith('billingAccounts/'):
            account_id = 'billingAccounts/{}'.format(account_id)
        return account_id


class _LoggingProjectsSinksRepository(
        repository_mixins.ListQueryMixin,
        _base_repository.GCPRepository):
    """Implementation of Logging Projects Sinks repository."""

    def __init__(self, **kwargs):
        """Constructor.

        Args:
            **kwargs (dict): The args to pass into GCPRepository.__init__()
        """
        super(_LoggingProjectsSinksRepository, self).__init__(
            key_field='parent', max_results_field='pageSize',
            component='projects.sinks', **kwargs)

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


class StackdriverLoggingClient(object):
    """Stackdriver Logging Client."""

    def __init__(self, global_configs, **kwargs):
        """Initialize.

        Args:
            global_configs (dict): Global configurations.
            **kwargs (dict): The kwargs.
        """
        max_calls, quota_period = api_helpers.get_ratelimiter_config(
            global_configs, API_NAME)

        self.repository = StackdriverLoggingRepositoryClient(
            quota_max_calls=max_calls,
            quota_period=quota_period,
            use_rate_limiter=kwargs.get('use_rate_limiter', True))

    def get_organization_sinks(self, org_id):
        """Get information about organization sinks.
        Args:
            org_id (str): The id of the organization.
        Returns:
            list: The response of retrieving the organization sinks.
        Raises:
            ApiExecutionError: ApiExecutionError is raised if the call to the
                GCP API fails.
        """
        name = self.repository.organizations_sinks.get_name(org_id)

        try:
            paged_results = self.repository.organizations_sinks.list(name)
            flattened_results = api_helpers.flatten_list_results(paged_results,
                                                                 'sinks')
            LOGGER.debug('Getting information about organization sinks,'
                         ' org_id = %s, flattened_results = %s',
                         org_id, flattened_results)
            return flattened_results
        except (errors.HttpError, HttpLib2Error) as e:
            api_exception = api_errors.ApiExecutionError(
                'organizations_sinks', e, 'name', name)
            LOGGER.exception(api_exception)
            raise api_exception

    def get_folder_sinks(self, folder_id):
        """Get information about folder sinks.
        Args:
            folder_id (str): The id of the folder.
        Returns:
            list: The response of retrieving the folder sinks.
        Raises:
            ApiExecutionError: ApiExecutionError is raised if the call to the
                GCP API fails.
        """
        name = self.repository.folders_sinks.get_name(folder_id)

        try:
            paged_results = self.repository.folders_sinks.list(name)
            flattened_results = api_helpers.flatten_list_results(paged_results,
                                                                 'sinks')
            LOGGER.debug('Getting information about folder sinks,'
                         ' folder_id = %s, flattened_results = %s',
                         folder_id, flattened_results)
            return flattened_results
        except (errors.HttpError, HttpLib2Error) as e:
            api_exception = api_errors.ApiExecutionError(
                'folders_sinks', e, 'name', name)
            LOGGER.exception(api_exception)
            raise api_exception

    def get_billing_account_sinks(self, account_id):
        """Get information about billing_account sinks.
        Args:
            account_id (str): The id of the billing account.
        Returns:
            list: The response of retrieving the billing_account sinks.
        Raises:
            ApiExecutionError: ApiExecutionError is raised if the call to the
                GCP API fails.
        """
        name = self.repository.billing_accounts_sinks.get_name(account_id)

        try:
            paged_results = self.repository.billing_accounts_sinks.list(name)
            flattened_results = api_helpers.flatten_list_results(paged_results,
                                                                 'sinks')
            LOGGER.debug('Getting information about billing_account sinks,'
                         ' billing_account_id = %s, flattened_results = %s',
                         account_id, flattened_results)
            return flattened_results
        except (errors.HttpError, HttpLib2Error) as e:
            api_exception = api_errors.ApiExecutionError(
                'billing_accounts_sinks', e, 'name', name)
            LOGGER.exception(api_exception)
            raise api_exception

    def get_project_sinks(self, project_id):
        """Get information about project sinks.
        Args:
            project_id (str): The id of the project.
        Returns:
            list: The response of retrieving the project sinks.
        Raises:
            ApiExecutionError: ApiExecutionError is raised if the call to the
                GCP API fails.
        """
        name = self.repository.projects_sinks.get_name(project_id)

        try:
            paged_results = self.repository.projects_sinks.list(name)
            flattened_results = api_helpers.flatten_list_results(paged_results,
                                                                 'sinks')
            LOGGER.debug('Getting information about project sinks,'
                         ' project_id = %s, flattened_results = %s',
                         project_id, flattened_results)
            return flattened_results
        except (errors.HttpError, HttpLib2Error) as e:
            api_exception = api_errors.ApiExecutionError(
                'projects_sinks', e, 'name', name)
            LOGGER.exception(api_exception)
            raise api_exception
