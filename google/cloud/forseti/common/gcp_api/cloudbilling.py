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

"""Wrapper for Cloud Billing API client."""
from googleapiclient import errors
from httplib2 import HttpLib2Error

from google.cloud.forseti.common.gcp_api import _base_repository
from google.cloud.forseti.common.gcp_api import api_helpers
from google.cloud.forseti.common.gcp_api import errors as api_errors
from google.cloud.forseti.common.gcp_api import repository_mixins
from google.cloud.forseti.common.util import logger

LOGGER = logger.get_logger(__name__)
API_NAME = 'cloudbilling'


class CloudBillingRepositoryClient(_base_repository.BaseRepositoryClient):
    """Cloud Billing API Respository."""

    def __init__(self,
                 quota_max_calls=None,
                 quota_period=60.0,
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

        self._billing_accounts = None
        self._projects = None

        super(CloudBillingRepositoryClient, self).__init__(
            API_NAME, versions=['v1'],
            quota_max_calls=quota_max_calls,
            quota_period=quota_period,
            use_rate_limiter=use_rate_limiter)

    # Turn off docstrings for properties.
    # pylint: disable=missing-return-doc, missing-return-type-doc
    @property
    def billing_accounts(self):
        """Returns a _CloudBillingBillingAccountsRepository instance."""
        if not self._billing_accounts:
            self._billing_accounts = self._init_repository(
                _CloudBillingBillingAccountsRepository)
        return self._billing_accounts
    # pylint: enable=missing-return-doc, missing-return-type-doc

    # Turn off docstrings for properties.
    # pylint: disable=missing-return-doc, missing-return-type-doc
    @property
    def projects(self):
        """Returns a _CloudBillingProjectsRepository instance."""
        if not self._projects:
            self._projects = self._init_repository(
                _CloudBillingProjectsRepository)
        return self._projects
    # pylint: enable=missing-return-doc, missing-return-type-doc


class _CloudBillingBillingAccountsRepository(
        repository_mixins.GetIamPolicyQueryMixin,
        repository_mixins.ListQueryMixin,
        _base_repository.GCPRepository):
    """Implementation of Cloud Billing BillingAccounts repository."""

    def __init__(self, **kwargs):
        """Constructor.

        Args:
            **kwargs (dict): The args to pass into GCPRepository.__init__()
        """
        super(_CloudBillingBillingAccountsRepository, self).__init__(
            list_key_field=None, max_results_field='pageSize',
            component='billingAccounts', **kwargs)

    @staticmethod
    def get_name(account_id):
        """Format's a billing account ID to pass to the API

        Args:
            account_id (str): The billing account id to query, either just the
                id or the id prefixed with 'billingAccounts/'.

        Returns:
            str: The formatted resource name.
        """
        if account_id and not account_id.startswith('billingAccounts/'):
            account_id = 'billingAccounts/{}'.format(account_id)
        return account_id


class _CloudBillingProjectsRepository(_base_repository.GCPRepository):
    """Implementation of Cloud Billing Projects repository."""

    def __init__(self, **kwargs):
        """Constructor.

        Args:
            **kwargs (dict): The args to pass into GCPRepository.__init__()
        """
        super(_CloudBillingProjectsRepository, self).__init__(
            component='projects', **kwargs)

    def get_billing_info(self, name, fields=None):
        """Gets the billing information for a project.

        Args:
            name (str): The project name to query in the format
                projects/{project_id}.
            fields (str): Fields to include in the response - partial response.

        Returns:
            dict: The response from the API.
        """
        arguments = {'name': name,
                     'fields': fields}
        return self.execute_query(
            verb='getBillingInfo',
            verb_arguments=arguments,
        )

    @staticmethod
    def get_name(project_id):
        """Format's a project_id to pass in to .get().

        Args:
            project_id (str): The project id to query, either just the
                id or the id prefixed with 'projects/'.

        Returns:
            str: The formatted resource name.
        """
        if not project_id.startswith('projects/'):
            project_id = 'projects/{}'.format(project_id)
        return project_id


class CloudBillingClient(object):
    """Cloud Billing Client."""

    def __init__(self, global_configs, **kwargs):
        """Initialize.

        Args:
            global_configs (dict): Global configurations.
            **kwargs (dict): The kwargs.
        """
        max_calls, quota_period = api_helpers.get_ratelimiter_config(
            global_configs, API_NAME)

        self.repository = CloudBillingRepositoryClient(
            quota_max_calls=max_calls,
            quota_period=quota_period,
            use_rate_limiter=kwargs.get('use_rate_limiter', True))

    def get_billing_info(self, project_id):
        """Gets the billing information for a project.

        Args:
            project_id (int): The project id for a GCP project.

        Returns:
            dict: A ProjectBillingInfo resource.
            https://cloud.google.com/billing/reference/rest/v1/ProjectBillingInfo

            {
              "name": string,
              "projectId": string,
              "billingAccountName": string,
              "billingEnabled": boolean,
            }

        Raises:
            ApiExecutionError: ApiExecutionError is raised if the call to the
                GCP API fails.
        """

        try:
            name = self.repository.projects.get_name(project_id)
            results = self.repository.projects.get_billing_info(name)
            LOGGER.debug('Getting the billing information for a project,'
                         ' project_id = %s, results = %s', project_id, results)
            return results
        except (errors.HttpError, HttpLib2Error) as e:
            if isinstance(e, errors.HttpError) and e.resp.status == 404:
                LOGGER.warn(e)
                return {}
            api_exception = api_errors.ApiExecutionError(
                'billing_info', e, 'project_id', project_id)
            LOGGER.exception(api_exception)
            raise api_exception

    def get_billing_accounts(self, master_account_id=None):
        """Gets all billing accounts the authenticated user has access to.

        If no master account is specified, then all billing accounts the caller
        has visibility to are returned. Otherwise retuns all subaccounts of the
        specified master billing account.


        Args:
            master_account_id (str): If set, only return subaccounts under this
                master billing account.

        Returns:
            list: A list of BillingAccount resources.
            https://cloud.google.com/billing/reference/rest/v1/billingAccounts

            {
              "name": string,
              "open": boolean,
              "displayName": string,
              "masterBillingAccount": string,
            }

        Raises:
            ApiExecutionError: ApiExecutionError is raised if the call to the
                GCP API fails.
        """
        filters = ''
        if master_account_id:
            filters = 'master_billing_account={}'.format(
                self.repository.billing_accounts.get_name(master_account_id))

        try:
            paged_results = self.repository.billing_accounts.list(
                filter=filters)
            flattened_results = api_helpers.flatten_list_results(
                paged_results, 'billingAccounts')
            LOGGER.debug('Getting billing_accounts,'
                         ' master_account_id = %s, flattened_results = %s',
                         master_account_id, flattened_results)
            return flattened_results
        except (errors.HttpError, HttpLib2Error) as e:
            api_exception = api_errors.ApiExecutionError(
                'billing_accounts', e, 'filter', filters)
            LOGGER.exception(api_exception)
            raise api_exception

    def get_billing_acct_iam_policies(self, account_id):
        """Gets the IAM policies for the given billing account.

        Args:
            account_id (str): The billing account id.

        Returns:
            dict: An IAM Policy resource.
            https://cloud.google.com/billing/reference/rest/v1/Policy

            {
              "bindings": list,
              "auditConfigs": list,
              "etag": string,
            }

        Raises:
            ApiExecutionError: ApiExecutionError is raised if the call to the
                GCP API fails.
        """
        name = self.repository.billing_accounts.get_name(account_id)

        try:
            results = self.repository.billing_accounts.get_iam_policy(
                name, include_body=False)
            LOGGER.debug('Getting IAM policies for a given billing account,'
                         ' account_id = %s, results = %s', account_id, results)
            return results
        except (errors.HttpError, HttpLib2Error) as e:
            api_exception = api_errors.ApiExecutionError(account_id, e)
            LOGGER.exception(api_exception)
            raise api_exception
