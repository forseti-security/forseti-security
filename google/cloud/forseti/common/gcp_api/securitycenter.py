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
                 use_rate_limiter=True,
                 version=None):
        """Constructor.
        Args:
            quota_max_calls (int): Allowed requests per <quota_period> for the
                API.
            quota_period (float): The time period to track requests over.
            use_rate_limiter (bool): Set to false to disable the use of a rate
                limiter for this service.
            version (str): The version of the API to use.
        """
        LOGGER.debug('Initializing SecurityCenterRepositoryClient')
        if not quota_max_calls:
            use_rate_limiter = False

        self._findings = None

        self.version = version
        use_versioned_discovery_doc = False
        if self.version == 'v1beta1':
            use_versioned_discovery_doc = True
            # alpha would use the discovery_doc without version in the name

        super(SecurityCenterRepositoryClient, self).__init__(
            'securitycenter', versions=[self.version],
            quota_max_calls=quota_max_calls,
            quota_period=quota_period,
            use_rate_limiter=use_rate_limiter,
            use_versioned_discovery_doc=use_versioned_discovery_doc)

    # Turn off docstrings for properties.
    # pylint: disable=missing-return-doc, missing-return-type-doc
    @property
    def findings(self):
        """Returns _SecurityCenterOrganizationsFindingsRepository instance."""
        if not self._findings:
            self._findings = self._init_repository(
                _SecurityCenterOrganizationsFindingsRepository,
                version=self.version)
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

        # pylint: disable=protected-access
        if kwargs.get('gcp_service')._resourceDesc.get('version') == 'v1beta1':
            component = 'organizations.sources.findings'
        else:
            # alpha api
            component = 'organizations.findings'
        # pylint: enable=protected-access

        super(_SecurityCenterOrganizationsFindingsRepository, self).__init__(
            component=component, **kwargs)


class SecurityCenterClient(object):
    """Cloud Security Command Center Client.

    https://cloud.google.com/security-command-center/docs/reference/rest
    """

    def __init__(self, version=None):
        """Initialize.

        TODO: Add api quota configs here.
        max_calls, quota_period = api_helpers.get_ratelimiter_config(
            inventory_configs.api_quota_configs, 'securitycenter')

        Args:
            version (str): The version of the API to use.
        """
        LOGGER.debug('Initializing SecurityCenterClient with version: %s',
                     version)
        self.repository = SecurityCenterRepositoryClient(version=version)

    def create_finding(self, finding, organization_id=None, source_id=None,
                       finding_id=None):
        """Creates a finding in CSCC.

        Args:
            finding (dict): Forseti violation in CSCC format.
            organization_id (str): The id prefixed with 'organizations/'.
            source_id (str): Unique ID assigned by CSCC, to the organization
                that the violations are originating from.
            finding_id (str): id hash of the CSCC finding

        Returns:
            dict: An API response containing one page of results.
        """
        if source_id:
            # beta api
            try:
                LOGGER.debug('Creating finding with beta api.')
                response = self.repository.findings.create(
                    arguments={
                        'body': finding,
                        'parent': source_id,
                        'findingId': finding_id
                    }
                )
                LOGGER.debug('Created finding response with CSCC beta api: %s',
                             response)
                return response
            # handle 409, finding exists
            except (errors.HttpError, HttpLib2Error) as e:
                LOGGER.exception(
                    'Unable to create CSCC finding: Resource: %s', finding)
                violation_data = (
                    finding.get('source_properties').get('violation_data'))
                raise api_errors.ApiExecutionError(violation_data, e)

        # alpha api
        try:
            LOGGER.debug('Creating finding with alpha api.')
            response = self.repository.findings.create(
                arguments={
                    'body': {'sourceFinding': finding},
                    'orgName': organization_id
                }
            )
            LOGGER.debug('Created finding response with CSCC alpha: %s',
                         response)
            return response
        except (errors.HttpError, HttpLib2Error) as e:
            LOGGER.exception(
                'Unable to create CSCC finding: Resource: %s', finding)
            full_name = (
                finding.get('properties').get('violation_data')
                .get('full_name'))
            raise api_errors.ApiExecutionError(full_name, e)
