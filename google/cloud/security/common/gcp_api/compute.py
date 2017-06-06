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
from ratelimiter import RateLimiter

from google.cloud.security.common.gcp_api import _base_client
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

    @staticmethod
    def _flatten_aggregated_list(aggregated_iterable, item_key):
        """Flatten a split-up list as returned by GCE "aggregatedList" API.

        The compute API's aggregatedList methods return a structure in
        the form:
          {
            items: {
              $group_value_1: {
                $item_key: [$items]
              },
              $group_value_2: {
                $item_key: [$items]
              },
              $group_value_3: {
                "warning": {
                  message: "There are no results for ..."
                }
              },
              ...,
              $group_value_n, {
                $item_key: [$items]
              },
            }
          }
        where each "$group_value_n" is a particular element in the
        aggregation, e.g. a particular zone or group or whatever, and
        "$item_key" is some type-specific resource name, e.g.
        "backendServices" for an aggregated list of backend services.

        This method takes such a structure and yields a simple list of
        all $items across all of the groups.

        Args:
          aggregated_iterable: An iterable returning a result from an
                               aggregatedList call.
          item_key: The name of the key within the inner "items" lists
                    containing the objects of interest.

        Return:
          A list of items.
        """
        items = []
        for aggregated_results in aggregated_iterable:
            aggregated_items = aggregated_results.get('items', {})
            for items_for_grouping in aggregated_items.values():
                for item in items_for_grouping.get(item_key, []):
                    items.append(item)
        return items

    @staticmethod
    def _flatten_list(item_pages_iterator):
        """Returns the 'items' entries from GCE API results.

        GCE 'list' APIs return results in the form:
          {'items': [...]}
        with one dictionary for each "page" of results. This method flattens
        that to a simple list of items.

        Args:
            item_pages_iterator: An iterator returning a page of GCE list API
                                 results.

        Return:
            A list of GCE resources.
        """
        results = []
        for page in item_pages_iterator:
            results.extend(page.get('items', []))
        return results

    def get_backend_services(self, project_id):
        """Get the backend services for a project.

        Args:
            project_id: The project id.

        Return:
            A list of backend services for this project.

        Raise:
            api_errors.ApiExecutionError if API raises an error.
        """
        backend_services_api = self.service.backendServices()
        list_request = backend_services_api.aggregatedList(
            project=project_id)
        list_next_request = backend_services_api.aggregatedList_next
        return self._flatten_aggregated_list(
            self._build_paged_result(list_request, backend_services_api,
                                     self.rate_limiter,
                                     next_stub=list_next_request),
            'backendServices')

    def get_forwarding_rules(self, project_id, region=None):
        """Get the forwarding rules for a project.

        If no region name is specified, use aggregatedList() to query for
        forwarding rules in all regions.

        Args:
            project_id: The project id.
            region: The region name.

        Return:
            A list of forwarding rules for this project.

        Raise:
            api_errors.ApiExecutionError if API raises an error.
        """
        forwarding_rules_api = self.service.forwardingRules()
        # pylint: disable=no-else-return
        if region:
            return self._flatten_list(
                self._build_paged_result(
                    forwarding_rules_api.list(
                        project=project_id, region=region),
                    forwarding_rules_api,
                    self.rate_limiter))
        else:
            return self._flatten_aggregated_list(
                self._build_paged_result(
                    forwarding_rules_api.aggregatedList(
                        project=project_id),
                    forwarding_rules_api,
                    self.rate_limiter,
                    next_stub=forwarding_rules_api.aggregatedList_next),
                'forwardingRules')

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
        return self._flatten_list(
            self._build_paged_result(request, firewall_rules_api,
                                     self.rate_limiter))

    def get_instances(self, project_id):
        """Get the instances for a project.

        Args:
            project_id: The project id.

        Return:
            A list of instances for this project.

        Raise:
            api_errors.ApiExecutionError if API raises an error.
        """
        instances_api = self.service.instances()
        list_request = instances_api.aggregatedList(
            project=project_id)
        list_next_request = instances_api.aggregatedList_next
        return self._flatten_aggregated_list(
            self._build_paged_result(list_request, instances_api,
                                     self.rate_limiter,
                                     next_stub=list_next_request),
            'instances')

    def get_instance_groups(self, project_id):
        """Get the instance groups for a project.

        Args:
            project_id: The project id.

        Return:
            A list of instance groups for this project.

        Raise:
            api_errors.ApiExecutionError if API raises an error.
        """
        instance_groups_api = self.service.instanceGroups()
        list_request = instance_groups_api.aggregatedList(
            project=project_id)
        list_next_request = instance_groups_api.aggregatedList_next
        return self._flatten_aggregated_list(
            self._build_paged_result(list_request, instance_groups_api,
                                     self.rate_limiter,
                                     next_stub=list_next_request),
            'instanceGroups')

    def get_instance_templates(self, project_id):
        """Get the instance templates for a project.

        Args:
            project_id: The project id.

        Return:
            A list of instance templates for this project.

        Raise:
            api_errors.ApiExecutionError if API raises an error.
        """
        instance_templates_api = self.service.instanceTemplates()
        list_request = instance_templates_api.list(
            project=project_id)
        return self._flatten_list(
            self._build_paged_result(list_request, instance_templates_api,
                                     self.rate_limiter))

    def get_instance_group_managers(self, project_id):
        """Get the instance group managers for a project.

        Args:
            project_id: The project id.

        Return:
            A list of instance group managers for this project.

        Raise:
            api_errors.ApiExecutionError if API raises an error.
        """
        instance_group_managers_api = self.service.instanceGroupManagers()
        list_request = instance_group_managers_api.aggregatedList(
            project=project_id)
        list_next_request = instance_group_managers_api.aggregatedList_next
        return self._flatten_aggregated_list(
            self._build_paged_result(list_request, instance_group_managers_api,
                                     self.rate_limiter,
                                     next_stub=list_next_request),
            'instanceGroupManagers')
