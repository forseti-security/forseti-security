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

import json
import os

from googleapiclient import errors
from httplib2 import HttpLib2Error

from google.cloud.security.common.gcp_api import _base_repository
from google.cloud.security.common.gcp_api import errors as api_errors
from google.cloud.security.common.util import log_util


LOGGER = log_util.get_logger(__name__)


def _api_not_enabled(error):
    """Checks if the error is due to the API not being enabled for project.

    Args:
        error (Exception): The error to check.

    Returns:
        tuple: (bool, str) True, API not enabled reason if API is not enabled
            or False, '' if there is a different exception.
    """
    if isinstance(error, errors.HttpError):
        if (error.resp.status == 403 and
                error.resp.get('content-type', '').startswith(
                    'application/json')):

            # If a project doesn't have the necessary API enabled, Google
            # will return an error domain=usageLimits and
            # reason=accessNotConfigured. Clients may wish to handle this
            # error in some particular way. For instance, when listing
            # resources, it might be treated as "no resources of that type
            # are present", if the API would need to be enabled in order
            # to create the resources in question!
            #
            # So, if we find that specific error, raise a different
            # exception to indicate it to callers. Otherwise, propagate
            # the initial exception.
            error_details = json.loads(error.content.decode('utf-8'))
            all_errors = error_details.get('error', {}).get('errors', [])
            api_disabled_errors = [
                error for error in all_errors
                if (error.get('domain') == 'usageLimits'
                    and error.get('reason') == 'accessNotConfigured')]
            if (api_disabled_errors and
                    len(api_disabled_errors) == len(all_errors)):
                return (True, api_disabled_errors[0].get('extendedHelp', ''))
    return (False, '')


# pylint: disable=invalid-name
def _flatten_aggregated_list_results(project_id, paged_results, item_key,
                                     sort_key='name'):
    """Flatten results and handle exceptions.

    Args:
        project_id (str): The project id the results are for.
        paged_results (list): A list of paged API response objects.
            [{page 1 results}, {page 2 results}, {page 3 results}, ...]
        item_key (str): The name of the key within the inner "items" lists
            containing the objects of interest.
        sort_key (str): The name of the key to sort the results by before
            returning.

    Returns:
        list: A sorted list of items.

    Raises:
        ApiNotEnabledError: Raised if the API is not enabled for the project.
        ApiExecutionError: Raised if there is another error while calling the
            API method.
    """
    try:
        return sorted(
            _base_repository.flatten_aggregated_list_results(paged_results,
                                                             item_key),
            key=lambda d: d.get(sort_key, ''))
    except (errors.HttpError, HttpLib2Error) as e:
        api_not_enabled, details = _api_not_enabled(e)
        if api_not_enabled:
            raise api_errors.ApiNotEnabledError(details, e)
        raise api_errors.ApiExecutionError(project_id, e)
# pylint: enable=invalid-name


def _flatten_list_results(project_id, paged_results, item_key):
    """Flatten results and handle exceptions.

    Args:
        project_id (str): The project id the results are for.
        paged_results (list): A list of paged API response objects.
            [{page 1 results}, {page 2 results}, {page 3 results}, ...]
        item_key (str): The name of the key within the inner "items" lists
            containing the objects of interest.

    Returns:
        list: A list of items.

    Raises:
        ApiNotEnabledError: Raised if the API is not enabled for the project.
        ApiExecutionError: Raised if there is another error while calling the
            API method.
    """
    try:
        return _base_repository.flatten_list_results(paged_results, item_key)
    except (errors.HttpError, HttpLib2Error) as e:
        api_not_enabled, details = _api_not_enabled(e)
        if api_not_enabled:
            raise api_errors.ApiNotEnabledError(details, e)
        raise api_errors.ApiExecutionError(project_id, e)


# pylint: disable=too-many-instance-attributes
class ComputeRepository(_base_repository.BaseRepositoryClient):
    """Compute API Respository."""

    def __init__(self,
                 quota_max_calls=None,
                 quota_period=100.0,
                 use_rate_limiter=True):
        """Constructor.

        Args:
          quota_max_calls (int): Allowed requests per <quota_period> for the
              API.
          quota_period (float): The time period to limit the quota_requests to.
          use_rate_limiter (bool): Set to false to disable the use of a rate
              limiter for this service.
        """
        if not quota_max_calls:
            use_rate_limiter = False

        self._backend_services = None
        self._forwarding_rules = None
        self._firewalls = None
        self._instance_group_managers = None
        self._instance_groups = None
        self._instances = None
        self._instance_templates = None
        self._region_instance_groups = None

        super(ComputeRepository, self).__init__(
            'compute', versions=['beta', 'v1'],
            quota_max_calls=quota_max_calls,
            quota_period=quota_period,
            use_rate_limiter=use_rate_limiter)

    # Turn off docstrings for properties.
    # pylint: disable=missing-return-doc, missing-return-type-doc
    @property
    def backend_services(self):
        """Returns a _ComputeBackendServicesRepository instance."""
        # The beta api provides IAP data.
        # TODO: Remove beta when it becomes GA.
        if not self._backend_services:
            self._backend_services = self._init_repository(
                _ComputeBackendServicesRepository, version='beta')

        return self._backend_services

    @property
    def forwarding_rules(self):
        """Returns a _ComputeForwardingRulesRepository instance."""
        if not self._forwarding_rules:
            self._forwarding_rules = self._init_repository(
                _ComputeForwardingRulesRepository)

        return self._forwarding_rules

    @property
    def firewalls(self):
        """Returns a _ComputeFirewallsRepository instance."""
        # The beta api provides more complete firewall rules data.
        # TODO: Remove beta when it becomes GA.
        if not self._firewalls:
            self._firewalls = self._init_repository(
                _ComputeFirewallsRepository, version='beta')

        return self._firewalls

    @property
    def instance_group_managers(self):
        """Returns a _ComputeInstanceGroupManagersRepository instance."""
        if not self._instance_group_managers:
            self._instance_group_managers = self._init_repository(
                _ComputeInstanceGroupManagersRepository)

        return self._instance_group_managers

    @property
    def instance_groups(self):
        """Returns a _ComputeInstanceGroupsRepository instance."""
        if not self._instance_groups:
            self._instance_groups = self._init_repository(
                _ComputeInstanceGroupsRepository)

        return self._instance_groups

    @property
    def instances(self):
        """Returns a _ComputeInstancesRepository instance."""
        if not self._instances:
            self._instances = self._init_repository(
                _ComputeInstancesRepository)

        return self._instances

    @property
    def instance_templates(self):
        """Returns a _ComputeInstanceTemplatesRepository instance."""
        if not self._instance_templates:
            self._instance_templates = self._init_repository(
                _ComputeInstanceTemplatesRepository)

        return self._instance_templates

    @property
    def region_instance_groups(self):
        """Returns a _ComputeRegionInstanceGroupsRepository instance."""
        if not self._region_instance_groups:
            self._region_instance_groups = self._init_repository(
                _ComputeRegionInstanceGroupsRepository)

        return self._region_instance_groups
    # pylint: enable=missing-return-doc, missing-return-type-doc
# pylint: enable=too-many-instance-attributes


class _ComputeBackendServicesRepository(
        _base_repository.GCPRepository,
        _base_repository.AggregatedListQueryMixin):
    """Implementation of Compute Backend Services repository."""

    def __init__(self, **kwargs):
        """Constructor.

        Args:
          kwargs (dict): The args to pass into GCPRepository.__init__()
        """
        super(_ComputeBackendServicesRepository, self).__init__(
            component='backendServices', **kwargs)


class _ComputeForwardingRulesRepository(
        _base_repository.GCPRepository,
        _base_repository.AggregatedListQueryMixin):
    """Implementation of Compute Forwarding Rules repository."""

    def __init__(self, **kwargs):
        """Constructor.

        Args:
            kwargs (dict): The args to pass into GCPRepository.__init__()
        """
        super(_ComputeForwardingRulesRepository, self).__init__(
            component='forwardingRules', **kwargs)

    def list(self, resource, region, **kwargs):
        """List instances by zone.

        Args:
            resource (str): The project to query resources for.
            region (str): The region of the forwarding rules to query.
            kwargs (dict): Additional args to pass through to the base method.

        Returns:
            iterator: An iterator over each page of results from the API.
        """
        kwargs['region'] = region
        return _base_repository.ListQueryMixin.list(self, resource, **kwargs)


class _ComputeFirewallsRepository(
        _base_repository.GCPRepository,
        _base_repository.ListQueryMixin):
    """Implementation of Compute Forwarding Rules repository."""

    def __init__(self, **kwargs):
        """Constructor.

        Args:
            kwargs (dict): The args to pass into GCPRepository.__init__()
        """
        super(_ComputeFirewallsRepository, self).__init__(
            component='firewalls', **kwargs)


class _ComputeInstanceGroupManagersRepository(
        _base_repository.GCPRepository,
        _base_repository.AggregatedListQueryMixin):
    """Implementation of Compute Instance Group Managers repository."""

    def __init__(self, **kwargs):
        """Constructor.

        Args:
            kwargs (dict): The args to pass into GCPRepository.__init__()
        """
        super(_ComputeInstanceGroupManagersRepository, self).__init__(
            component='instanceGroupManagers', **kwargs)


class _ComputeInstanceGroupsRepository(
        _base_repository.GCPRepository,
        _base_repository.AggregatedListQueryMixin):
    """Implementation of Compute Instance Groups repository."""

    def __init__(self, **kwargs):
        """Constructor.

        Args:
            kwargs (dict): The args to pass into GCPRepository.__init__()
        """
        super(_ComputeInstanceGroupsRepository, self).__init__(
            component='instanceGroups', **kwargs)

    def list_instances(self, resource, instance_group, zone, **kwargs):
        """List instances for instance group.

        Args:
            resource (str): The project to query resources for.
            instance_group (str): The name of the instance group to query.
            zone (str): The zone of the instance group to query.
            kwargs (dict): Additional args to pass through to the base method.

        Returns:
            iterator: An iterator over each page of results from the API.
        """
        kwargs['instanceGroup'] = instance_group
        kwargs['zone'] = zone

        return _base_repository.ListQueryMixin.list(
            self, resource, verb='listInstances', **kwargs)



class _ComputeInstancesRepository(
        _base_repository.GCPRepository,
        _base_repository.AggregatedListQueryMixin):
    """Implementation of Compute Instances repository."""

    def __init__(self, **kwargs):
        """Constructor.

        Args:
            kwargs (dict): The args to pass into GCPRepository.__init__()
        """
        super(_ComputeInstancesRepository, self).__init__(
            component='instances', **kwargs)

    def list(self, resource, zone, **kwargs):
        """List instances by zone.

        Args:
            resource (str): The project to query resources for.
            zone (str): The zone of the instance group to query.
            kwargs (dict): Additional args to pass through to the base method.

        Returns:
            iterator: An iterator over each page of results from the API.
        """
        kwargs['zone'] = zone
        return _base_repository.ListQueryMixin.list(self, resource, **kwargs)


class _ComputeInstanceTemplatesRepository(
        _base_repository.GCPRepository,
        _base_repository.ListQueryMixin):
    """Implementation of Compute Instance Templates repository."""

    def __init__(self, **kwargs):
        """Constructor.

        Args:
            kwargs (dict): The args to pass into GCPRepository.__init__()
        """
        super(_ComputeInstanceTemplatesRepository, self).__init__(
            component='instanceTemplates', **kwargs)


class _ComputeRegionInstanceGroupsRepository(
        _base_repository.GCPRepository,
        _base_repository.ListQueryMixin):
    """Implementation of Compute Region Instance Groups repository."""

    def __init__(self, **kwargs):
        """Constructor.

        Args:
            kwargs (dict): The args to pass into GCPRepository.__init__()
        """
        super(_ComputeRegionInstanceGroupsRepository, self).__init__(
            component='regionInstanceGroups', **kwargs)

    def list_instances(self, resource, instance_group, region, **kwargs):
        """List instances for instance group.

        Args:
            resource (str): The project to query resources for.
            instance_group (str): The name of the instance group to query.
            region (str): The region of the instance group to query.
            kwargs (dict): Additional args to pass through to the base method.

        Returns:
            iterator: An iterator over each page of results from the API.
        """
        kwargs['instanceGroup'] = instance_group
        kwargs['region'] = region

        return _base_repository.ListQueryMixin.list(
            self, resource, verb='listInstances', **kwargs)


class ComputeClient(object):
    """Compute Client."""

    DEFAULT_QUOTA_PERIOD = 1.0

    def __init__(self, global_configs, **kwargs):
        """Initialize.

        Args:
            global_configs (dict): Forseti config.
            **kwargs (dict): The kwargs.
        """
        max_calls = global_configs.get('max_compute_api_calls_per_second')
        self.repository = ComputeRepository(
            quota_max_calls=max_calls,
            quota_period=self.DEFAULT_QUOTA_PERIOD,
            use_rate_limiter=kwargs.get('use_rate_limiter', True))

    # TODO: Migrate helper functions from gce_firewall_enforcer.py
    # ComputeFirewallAPI class.

    def get_backend_services(self, project_id):
        """Get the backend services for a project.

        Args:
            project_id (str): The project id.

        Return:
            list: A list of backend services for this project.
        """
        paged_results = self.repository.backend_services.aggregated_list(
            project_id)
        return _flatten_aggregated_list_results(project_id, paged_results,
                                                'backendServices')

    def get_forwarding_rules(self, project_id, region=None):
        """Get the forwarding rules for a project.

        If no region name is specified, use aggregatedList() to query for
        forwarding rules in all regions.

        Args:
            project_id (str): The project id.
            region (str): The region name.

        Return:
            list: A list of forwarding rules for this project.
        """
        repository = self.repository.forwarding_rules
        if region:
            paged_results = repository.list(project_id, region)
            results = _flatten_list_results(project_id, paged_results, 'items')
        else:
            paged_results = repository.aggregated_list(project_id)
            results = _flatten_aggregated_list_results(project_id,
                                                       paged_results,
                                                       'forwardingRules')
        return results

    def get_firewall_rules(self, project_id):
        """Get the firewall rules for a given project id.

        Args:
            project_id (str): The project id.

        Return:
            list: A list of firewall rules for this project id.
        """
        paged_results = self.repository.firewalls.list(project_id)
        return _flatten_list_results(project_id, paged_results, 'items')

    def get_instances(self, project_id, zone=None):
        """Get the instances for a project.

        Args:
            project_id (str): The project id.
            zone (str): The zone to list the instances in.

        Return:
            list: A list of instances for this project.
        """
        repository = self.repository.instances
        if zone:
            paged_results = repository.list(project_id, zone)
            results = _flatten_list_results(project_id, paged_results, 'items')
        else:
            paged_results = repository.aggregated_list(project_id)
            results = _flatten_aggregated_list_results(project_id,
                                                       paged_results,
                                                       'instances')
        return results

    def get_instance_group_instances(self, project_id, instance_group_name,
                                     region=None, zone=None):
        """Get the instance groups for a project.

        One and only one of zone (for zonal instance groups) and region
        (for regional instance groups) must be specified.

        Args:
            project_id (str): The project id.
            instance_group_name (str): The instance group's name.
            zone (str): The zonal instance group's zone.
            region (str): The regional instance group's region.

        Return:
            list: instance URLs for this instance group.

        Raises:
            ValueError: invalid combination of parameters
        """
        if not bool(zone) ^ bool(region):
            raise ValueError('One and only one of zone and region must be '
                             'specified.')
        if zone:
            repository = self.repository.instance_groups
            paged_results = repository.list_instances(
                project_id, instance_group_name, zone,
                fields='items/instance,nextPageToken',
                body={'instanceState': 'ALL'})

        else:
            repository = self.repository.region_instance_groups
            paged_results = repository.list_instances(
                project_id, instance_group_name, region,
                fields='items/instance,nextPageToken',
                body={'instanceState': 'ALL'})

        return [
            instance_data.get('instance')
            for instance_data in _flatten_list_results(
                project_id, paged_results, 'items')
            if 'instance' in instance_data
        ]

    def get_instance_groups(self, project_id):
        """Get the instance groups for a project.

        Args:
            project_id (str): The project id.

        Return:
            list: A list of instance groups for this project.
        """
        paged_results = self.repository.instance_groups.aggregated_list(
            project_id)

        instance_groups = sorted(
            _flatten_aggregated_list_results(project_id, paged_results,
                                             'instanceGroups'),
            key=lambda d: d.get('name'))
        for instance_group in instance_groups:
            instance_group['instance_urls'] = self.get_instance_group_instances(
                project_id,
                instance_group.get('name'),
                # Turn zone and region URLs into a names
                zone=os.path.basename(instance_group.get('zone', '')),
                region=os.path.basename(instance_group.get('region', '')))
        return instance_groups

    def get_instance_templates(self, project_id):
        """Get the instance templates for a project.

        Args:
            project_id (str): The project id.

        Return:
            list: A list of instance templates for this project.
        """
        paged_results = self.repository.instance_templates.list(project_id)
        return _flatten_list_results(project_id, paged_results, 'items')

    def get_instance_group_managers(self, project_id):
        """Get the instance group managers for a project.

        Args:
            project_id (str): The project id.

        Return:
            list: A list of instance group managers for this project.
        """
        paged_results = self.repository.instance_group_managers.aggregated_list(
            project_id)
        return _flatten_aggregated_list_results(project_id, paged_results,
                                                'instanceGroupManagers')
