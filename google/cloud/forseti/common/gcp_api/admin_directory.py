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

"""Wrapper for Admin Directory  API client."""
from googleapiclient import errors
from httplib2 import HttpLib2Error
from google.auth.exceptions import RefreshError

from google.cloud.forseti.common.gcp_api import _base_repository
from google.cloud.forseti.common.gcp_api import api_helpers
from google.cloud.forseti.common.gcp_api import errors as api_errors
from google.cloud.forseti.common.gcp_api import repository_mixins
from google.cloud.forseti.common.util import logger

LOGGER = logger.get_logger(__name__)

API_NAME = 'admin'

REQUIRED_SCOPES = frozenset([
    'https://www.googleapis.com/auth/admin.directory.group.readonly',
    'https://www.googleapis.com/auth/admin.directory.user.readonly'
])

GSUITE_AUTH_FAILURE_MESSAGE = (
    'Failed to retrieve G Suite data due to authentication '
    'failure. Please make sure your forseti_server_config.yaml '
    'file contains the most updated information and enable G '
    'Suite Groups Collection if you haven\'t done so. Instructions'
    ' on how to enable: https://forsetisecurity.org/docs/latest/'
    'configure/inventory/gsuite.html')


class AdminDirectoryRepositoryClient(_base_repository.BaseRepositoryClient):
    """Admin Directory API Respository Client."""

    def __init__(self,
                 credentials,
                 quota_max_calls=None,
                 quota_period=1.0,
                 use_rate_limiter=True):
        """Constructor.

        Args:
            credentials (object): An google.auth credentials object. The admin
                directory API needs a service account credential with delegated
                super admin role.
            quota_max_calls (int): Allowed requests per <quota_period> for the
                API.
            quota_period (float): The time period to track requests over.
            use_rate_limiter (bool): Set to false to disable the use of a rate
                limiter for this service.
        """
        if not quota_max_calls:
            use_rate_limiter = False

        self._groups = None
        self._members = None
        self._users = None

        super(AdminDirectoryRepositoryClient, self).__init__(
            API_NAME, versions=['directory_v1'],
            credentials=credentials,
            quota_max_calls=quota_max_calls,
            quota_period=quota_period,
            use_rate_limiter=use_rate_limiter)

    # Turn off docstrings for properties.
    # pylint: disable=missing-return-doc, missing-return-type-doc
    @property
    def groups(self):
        """Returns an _AdminDirectoryGroupsRepository instance."""
        if not self._groups:
            self._groups = self._init_repository(
                _AdminDirectoryGroupsRepository)
        return self._groups

    @property
    def members(self):
        """Returns an _AdminDirectoryMembersRepository instance."""
        if not self._members:
            self._members = self._init_repository(
                _AdminDirectoryMembersRepository)
        return self._members

    @property
    def users(self):
        """Returns an _AdminDirectoryUsersRepository instance."""
        if not self._users:
            self._users = self._init_repository(
                _AdminDirectoryUsersRepository)
        return self._users
    # pylint: enable=missing-return-doc, missing-return-type-doc


class _AdminDirectoryGroupsRepository(
        repository_mixins.ListQueryMixin,
        _base_repository.GCPRepository):
    """Implementation of Admin Directory Groups repository."""

    def __init__(self, **kwargs):
        """Constructor.

        Args:
            **kwargs (dict): The args to pass into GCPRepository.__init__()
        """
        super(_AdminDirectoryGroupsRepository, self).__init__(
            key_field='', component='groups', **kwargs)


class _AdminDirectoryMembersRepository(
        repository_mixins.ListQueryMixin,
        _base_repository.GCPRepository):
    """Implementation of Admin Directory Members repository."""

    def __init__(self, **kwargs):
        """Constructor.

        Args:
            **kwargs (dict): The args to pass into GCPRepository.__init__()
        """
        super(_AdminDirectoryMembersRepository, self).__init__(
            key_field='groupKey', component='members', **kwargs)


class _AdminDirectoryUsersRepository(
        repository_mixins.ListQueryMixin,
        _base_repository.GCPRepository):
    """Implementation of Admin Directory Users repository."""

    def __init__(self, **kwargs):
        """Constructor.

        Args:
            **kwargs (dict): The args to pass into GCPRepository.__init__()
        """
        super(_AdminDirectoryUsersRepository, self).__init__(
            key_field='', component='users', **kwargs)


class AdminDirectoryClient(object):
    """GSuite Admin Directory API Client."""

    def __init__(self, global_configs, **kwargs):
        """Initialize.

        Args:
            global_configs (dict): Global configurations.
            **kwargs (dict): The kwargs.
        """
        credentials = api_helpers.get_delegated_credential(
            global_configs.get('domain_super_admin_email'),
            REQUIRED_SCOPES)

        max_calls, quota_period = api_helpers.get_ratelimiter_config(
            global_configs, API_NAME)

        self.repository = AdminDirectoryRepositoryClient(
            credentials=credentials,
            quota_max_calls=max_calls,
            quota_period=quota_period,
            use_rate_limiter=kwargs.get('use_rate_limiter', True))

    def get_group_members(self, group_key):
        """Get all the members for specified groups.

        Args:
            group_key (str): The group's unique id assigned by the Admin API.

        Returns:
            list: A list of member objects from the API.

        Raises:
            api_errors.ApiExecutionError: If group member retrieval fails.
        """
        try:
            paged_results = self.repository.members.list(group_key)
            result = api_helpers.flatten_list_results(paged_results, 'members')
            LOGGER.debug('Getting all the members for group_key = %s,'
                         ' result = %s', group_key, result)
            return result
        except (errors.HttpError, HttpLib2Error) as e:
            raise api_errors.ApiExecutionError(group_key, e)

    def get_groups(self, customer_id='my_customer'):
        """Get all the groups for a given customer_id.

        A note on customer_id='my_customer'. This is a magic string instead
        of using the real customer id. See:

        https://developers.google.com/admin-sdk/directory/v1/guides/manage-groups#get_all_domain_groups

        Args:
            customer_id (str): The customer id to scope the request to.

        Returns:
            list: A list of group objects returned from the API.

        Raises:
            api_errors.ApiExecutionError: If groups retrieval fails.
            RefreshError: If the authentication fails.
        """
        try:
            paged_results = self.repository.groups.list(customer=customer_id)
            flattened_results = api_helpers.flatten_list_results(
                paged_results, 'groups')
            LOGGER.debug('Getting all the groups for customer_id = %s,'
                         ' flattened_results = %s',
                         customer_id, flattened_results)
            return flattened_results
        except RefreshError as e:
            # Authentication failed, log before raise.
            LOGGER.exception(GSUITE_AUTH_FAILURE_MESSAGE)
            raise e
        except (errors.HttpError, HttpLib2Error) as e:
            raise api_errors.ApiExecutionError('groups', e)

    def get_users(self, customer_id='my_customer'):
        """Get all the users for a given customer_id.

        A note on customer_id='my_customer'. This is a magic string instead
        of using the real customer id. See:

        https://developers.google.com/admin-sdk/directory/v1/guides/manage-groups#get_all_domain_groups

        Args:
            customer_id (str): The customer id to scope the request to.

        Returns:
            list: A list of user objects returned from the API.

        Raises:
            api_errors.ApiExecutionError: If groups retrieval fails.
            RefreshError: If the authentication fails.
        """
        try:
            paged_results = self.repository.users.list(customer=customer_id,
                                                       viewType='admin_view')
            flattened_results = api_helpers.flatten_list_results(
                paged_results, 'users')
            LOGGER.debug('Getting all the users for customer_id = %s,'
                         ' flattened_results = %s',
                         customer_id, flattened_results)
            return flattened_results
        except RefreshError as e:
            # Authentication failed, log before raise.
            LOGGER.exception(GSUITE_AUTH_FAILURE_MESSAGE)
            raise e
        except (errors.HttpError, HttpLib2Error) as e:
            raise api_errors.ApiExecutionError('users', e)
