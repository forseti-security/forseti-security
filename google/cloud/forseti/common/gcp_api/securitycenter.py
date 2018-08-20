# Copyright 2017 The Forseti Security Authors. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Wrapper for Cloud Security Command Center API client."""
from googleapiclient import errors
from httplib2 import HttpLib2Error

from google.cloud.forseti.common.gcp_api import _base_repository
from google.cloud.forseti.common.gcp_api import errors as api_errors
from google.cloud.forseti.common.gcp_api import repository_mixins
from google.cloud.forseti.common.util import logger

LOGGER = logger.get_logger(__name__)


class SecurityCenterRepositoryClient(_base_repository.BaseRepositoryClient):
    """SecurityCenter API Respository."""

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
        LOGGER.debug('Initializing SecurityCenterRepositoryClient')
        if not quota_max_calls:
            use_rate_limiter = False

        self._findings = None

        super(SecurityCenterRepositoryClient, self).__init__(
            'securitycenter', versions=['v1alpha3'],
            quota_max_calls=quota_max_calls,
            quota_period=quota_period,
            use_rate_limiter=use_rate_limiter)

    # Turn off docstrings for properties.
    # pylint: disable=missing-return-doc, missing-return-type-doc
    @property
    def findings(self):
        """Returns _SecurityCenterOrganizationsFindingsRepository instance."""
        if not self._findings:
            self._findings = self._init_repository(
                _SecurityCenterOrganizationsFindingsRepository)
        return self._findings
    # pylint: enable=missing-return-doc, missing-return-type-doc


class _SecurityCenterOrganizationsFindingsRepository(
        repository_mixins.CreateQueryMixin,
        _base_repository.GCPRepository):
    """Implementation of CSCC Organizations Findings repository."""

    def __init__(self, **kwargs):
        """Constructor.

        Args:
            **kwargs (dict): The args to pass into GCPRepository.__init__()
        """

        LOGGER.debug(
            'Creating _SecurityCenterOrganizationsFindingsRepositoryClient')
        super(_SecurityCenterOrganizationsFindingsRepository, self).__init__(
            component='organizations.findings', **kwargs)


class SecurityCenterClient(object):
    """Cloud Security Command Center Client.

    https://cloud.google.com/security-command-center/docs/reference/rest
    """

    def __init__(self):
        """Initialize.

        TODO: Add api quota configs here.
        max_calls, quota_period = api_helpers.get_ratelimiter_config(
            inventory_configs.api_quota_configs, 'securitycenter')
        """
        LOGGER.debug('Initializing SecurityCenterClient')
        self.repository = SecurityCenterRepositoryClient()

    def create_finding(self, organization_id, finding):
        """Creates a finding in CSCC.

        Args:
            organization_id (str): The id prefixed with 'organizations/'.
            finding (dict): Forseti violation in CSCC format.

        Returns:
            dict: An API response containing one page of results.
        """
        try:
            LOGGER.debug('Creating finding.')
            response = self.repository.findings.create(
                arguments={
                    'body': {'sourceFinding': finding},
                    'orgName': organization_id
                }
            )
            LOGGER.debug('Created finding response in CSCC: %s', response)
            return response
        except (errors.HttpError, HttpLib2Error) as e:
            LOGGER.exception(
                'Unable to create CSCC finding: Resource: %s', finding)
            full_name = (
                finding.get('properties').get('violation_data')
                .get('full_name'))
            raise api_errors.ApiExecutionError(full_name, e)
