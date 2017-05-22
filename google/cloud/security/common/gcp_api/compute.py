# Copyright 2017 Google Inc.
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

"""Wrapper for Compute API client."""

import gflags as flags
from googleapiclient.errors import HttpError
from httplib2 import HttpLib2Error
from ratelimiter import RateLimiter

from google.cloud.security.common.gcp_api import _base_client
from google.cloud.security.common.gcp_api import errors as api_errors
from google.cloud.security.common.util import log_util

FLAGS = flags.FLAGS

flags.DEFINE_integer('max_compute_api_calls_per_second', 20,
                     'Compute API calls per seconds.')

LOGGER = log_util.get_logger(__name__)


class ComputeClient(_base_client.BaseClient):
    """Compute Client."""

    API_NAME = 'compute'

    def __init__(self, credentials=None, version=None):
        # The beta api provides more complete firewall rules data.
        # TODO: Remove beta when it becomes GA.
        super(ComputeClient, self).__init__(
            credentials=credentials, api_name=self.API_NAME, version=version)
        self.rate_limiter = RateLimiter(
            FLAGS.max_compute_api_calls_per_second, 1)

    # TODO: Migrate helper functions from gce_firewall_enforcer.py
    # ComputeFirewallAPI class.

    def get_forwarding_rules(self, project_id, region=None):
        """Get the forwarding rules for a project.

        If no region name is specified, use aggregatedList() to query for
        forwarding rules in all regions.

        Args:
            project_id: The project id.
            region: The region name.

        Yield:
            An iterator of forwarding rules for this project.

        Raise:
            api_errors.ApiExecutionError if API raises an error.
        """
        forwarding_rules_api = self.service.forwardingRules()
        if region:
            list_request = forwarding_rules_api.list(
                project=project_id, region=region)
            list_next_request = forwarding_rules_api.list_next
        else:
            list_request = forwarding_rules_api.aggregatedList(
                project=project_id)
            list_next_request = forwarding_rules_api.aggregatedList_next

        try:
            while list_request is not None:
                response = self._execute(list_request)
                yield response
                list_request = list_next_request(
                    previous_request=list_request,
                    previous_response=response)
        except (HttpError, HttpLib2Error) as e:
            raise api_errors.ApiExecutionError('forwarding_rules', e)

    def get_firewall_rules(self, project_id):
        """Get the firewall rules for a given project id.

        Args:
            project_id: String of the project id. Project number is
                not accepted.

        Return:
            A list of firewall rules for this project id.
        """
        firewall_rules_api = self.service.firewalls()
        request = firewall_rules_api.list(project=project_id)

        paged_results = self._build_paged_result(request, firewall_rules_api,
                                                 self.rate_limiter)

        firewall_rules = []
        for page in paged_results:
            firewall_rules.extend(page.get('items', []))
        return firewall_rules
