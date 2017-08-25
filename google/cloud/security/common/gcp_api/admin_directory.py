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

"""Wrapper for Admin Directory  API client."""
from googleapiclient import errors
from httplib2 import HttpLib2Error

from google.cloud.security.common.gcp_api import _base_repository
from google.cloud.security.common.gcp_api import errors as api_errors
from google.cloud.security.common.util import log_util

LOGGER = log_util.get_logger(__name__)


class AdminDirectoryRepository(_base_repository.BaseRepositoryClient):
    """Admin Directory API Respository."""

    def __init__(self,
                 credentials,
                 quota_max_calls=None,
                 quota_period=1.0,
                 use_rate_limiter=True):
        """Constructor.

        Args:
          credentials (object): An oauth2client credentials object. The admin
              directory API needs a service account credential with delegated
              super admin role.
          quota_max_calls (int): Allowed requests per <quota_period> for the
              API.
          quota_period (float): The time period to limit the quota_requests to.
          use_rate_limiter (bool): Set to false to disable the use of a rate
              limiter for this service.
        """
        if not quota_max_calls:
            use_rate_limiter = False

        self._groups = None
        self._members = None

        super(AdminDirectoryRepository, self).__init__(
            'admin', versions=['directory_v1'],
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
    # pylint: enable=missing-return-doc, missing-return-type-doc


class _AdminDirectoryGroupsRepository(
        _base_repository.ListQueryMixin,
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
        _base_repository.ListQueryMixin,
        _base_repository.GCPRepository):
    """Implementation of Admin Directory Members repository."""

    def __init__(self, **kwargs):
        """Constructor.

        Args:
          **kwargs (dict): The args to pass into GCPRepository.__init__()
        """
        super(_AdminDirectoryMembersRepository, self).__init__(
            key_field='groupKey', component='members', **kwargs)


class AdminDirectoryClient(object):
    """GSuite Admin Directory API Client."""

    DEFAULT_QUOTA_TIMESPAN_PER_SECONDS = 100.0  # pylint: disable=invalid-name
    REQUIRED_SCOPES = frozenset([
        'https://www.googleapis.com/auth/admin.directory.group.readonly'
    ])

    def __init__(self, global_configs, **kwargs):
        """Initialize.

        Args:
            global_configs (dict): Global configurations.
            **kwargs (dict): The kwargs.
        """
        max_calls = global_configs.get('max_admin_api_calls_per_100_seconds')
        quota_period = self.DEFAULT_QUOTA_TIMESPAN_PER_SECONDS
        if not max_calls:
            max_calls = global_configs.get('max_admin_api_calls_per_day')
            quota_period = 86400.0
            LOGGER.error('Configuration is using a deprecated directive: '
                         '"max_admin_api_calls_per_day". Please switch to '
                         'using "max_admin_api_calls_per_100_seconds" instead. '
                         'See the sample configuration file for reference.')

        credentials = _base_repository.credential_from_keyfile(
            global_configs.get('groups_service_account_key_file'),
            self.REQUIRED_SCOPES,
            global_configs.get('domain_super_admin_email'))
        self.repository = AdminDirectoryRepository(
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
            return _base_repository.flatten_list_results(paged_results,
                                                         'members')
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
        """
        try:
            paged_results = self.repository.groups.list(customer=customer_id)
            return _base_repository.flatten_list_results(paged_results,
                                                         'groups')
        except (errors.HttpError, HttpLib2Error) as e:
            raise api_errors.ApiExecutionError('groups', e)
