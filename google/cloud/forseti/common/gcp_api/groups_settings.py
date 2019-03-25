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

"""Wrapper for Groups Settings  API client."""
from googleapiclient import errors
from httplib2 import HttpLib2Error
from google.auth.exceptions import RefreshError

from google.cloud.forseti.common.gcp_api import _base_repository
from google.cloud.forseti.common.gcp_api import api_helpers
from google.cloud.forseti.common.gcp_api import errors as api_errors
from google.cloud.forseti.common.gcp_api import repository_mixins
from google.cloud.forseti.common.util import logger

LOGGER = logger.get_logger(__name__)

API_NAME = 'groupssettings'

REQUIRED_SCOPES = frozenset([
    'https://www.googleapis.com/auth/apps.groups.settings'
])

GSUITE_AUTH_FAILURE_MESSAGE = (
    'Failed to retrieve G Suite Group Settings data due to authentication '
    'failure. Please make sure your forseti_server_config.yaml '
    'file contains the most updated information and enable G '
    'Suite Groups Collection if you haven\'t done so. Instructions'
    'on how to enable: https://forsetisecurity.org/docs/latest/'
    'configure/inventory/gsuite.html')


class GroupsSettingsRepositoryClient(_base_repository.BaseRepositoryClient):
    """Groups Settings API Respository Client."""

    def __init__(self,
                 credentials,
                 quota_max_calls=None,
                 quota_period=1.0,
                 use_rate_limiter=True):
        """Constructor.

        Args:
            credentials (object): An google.auth credentials object. The group
                settings API needs a service account credential with delegated
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

        super(GroupsSettingsRepositoryClient, self).__init__(
            API_NAME, versions=['v1'],
            credentials=credentials,
            quota_max_calls=quota_max_calls,
            quota_period=quota_period,
            use_rate_limiter=use_rate_limiter)

    # Turn off docstrings for properties.
    # pylint: disable=missing-return-doc, missing-return-type-doc
    @property
    def groups(self):
        """Returns a _GroupsSettingsGroupsRepository instance."""
        if not self._groups:
            self._groups = self._init_repository(
                _GroupsSettingsGroupsRepository)
        return self._groups
    # pylint: enable=missing-return-doc, missing-return-type-doc


class _GroupsSettingsGroupsRepository(
        repository_mixins.GetQueryMixin,
        _base_repository.GCPRepository):
    """Implementation of Groups Settings repository."""

    def __init__(self, **kwargs):
        """Constructor.

        Args:
            **kwargs (dict): The args to pass into GCPRepository.__init__()
        """
        super(_GroupsSettingsGroupsRepository, self).__init__(
            key_field='groupUniqueId', component='groups', **kwargs)


class GroupsSettingsClient(object):
    """GSuite Groups Settings API Client."""

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

        self.repository = GroupsSettingsRepositoryClient(
            credentials=credentials,
            quota_max_calls=max_calls,
            quota_period=quota_period,
            use_rate_limiter=kwargs.get('use_rate_limiter', True))

    def get_groups_settings(self, group_email):
        """Get the group settings for a given group.


        https://developers.google.com/admin-sdk/groups-settings/v1/reference/groups/get

        Args:
            group_email (str): The gsuite group email to scope the request to.

        Returns:
            dict:group settings for given group_email.

        Raises:
            api_errors.ApiExecutionError: If groups retrieval fails.
            RefreshError: If the authentication fails.
        """
        try:
            result = self.repository.groups.get(group_email)
            LOGGER.debug('Getting group settings information for group id = %s,'
                         ' result = %s',
                         group_email, result)
            return result
        except RefreshError as e:
            # Authentication failed, log before raise.
            LOGGER.exception(GSUITE_AUTH_FAILURE_MESSAGE)
            raise e
        except (errors.HttpError, HttpLib2Error) as e:
            raise api_errors.ApiExecutionError('groups', e)
