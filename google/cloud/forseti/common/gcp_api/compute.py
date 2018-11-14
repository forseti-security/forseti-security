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

"""Wrapper for Compute API client."""
# pylint: disable=too-many-lines
import json
import logging
import os
import time
from uuid import uuid4
from googleapiclient import errors
from httplib2 import HttpLib2Error

from google.cloud.forseti.common.gcp_api import _base_repository
from google.cloud.forseti.common.gcp_api import api_helpers
from google.cloud.forseti.common.gcp_api import errors as api_errors
from google.cloud.forseti.common.gcp_api import repository_mixins
from google.cloud.forseti.common.util import date_time
from google.cloud.forseti.common.util import logger

LOGGER = logger.get_logger(__name__)


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
                error.resp.get('content-type', '')
                .startswith('application/json')):

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
                err for err in all_errors
                if (err.get('domain') == 'usageLimits' and
                    err.get('reason') == 'accessNotConfigured')
            ]
            if (api_disabled_errors and
                    len(api_disabled_errors) == len(all_errors)):
                return True, api_disabled_errors[0].get('extendedHelp', '')
    return False, ''


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
            api_helpers.flatten_aggregated_list_results(paged_results,
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
        return api_helpers.flatten_list_results(paged_results, item_key)
    except (errors.HttpError, HttpLib2Error) as e:
        api_not_enabled, details = _api_not_enabled(e)
        if api_not_enabled:
            raise api_errors.ApiNotEnabledError(details, e)
        raise api_errors.ApiExecutionError(project_id, e)


def _debug_operation_response_time(project_id, operation):
    """Log timing details for a running operation if debug logs enabled.

    Args:
        project_id (str): The project id the operation was for.
        operation (dict): The last Operation resource returned from the
            API server.
    """
    if LOGGER.getEffectiveLevel() > logging.DEBUG:
        # Don't compute times if DEBUG logging is not enabled.
        return

    try:
        op_insert_timestamp = date_time.get_unix_timestamp_from_string(
            operation.get('insertTime', ''))
        op_start_timestamp = date_time.get_unix_timestamp_from_string(
            operation.get('startTime', ''))
        op_end_timestamp = date_time.get_unix_timestamp_from_string(
            operation.get('endTime', ''))
    except ValueError:
        op_insert_timestamp = op_start_timestamp = op_end_timestamp = 0

    op_wait_time = op_end_timestamp - op_insert_timestamp
    op_exec_time = op_end_timestamp - op_start_timestamp
    LOGGER.debug('Operation %s completed for project %s. Operation type: %s, '
                 'request time: %s, start time: %s, finished time: %s, '
                 'req->end seconds: %i, start->end seconds: %i.',
                 operation.get('name', ''),
                 project_id,
                 operation.get('operationType', ''),
                 operation.get('insertTime', ''),
                 operation.get('startTime', ''),
                 operation.get('endTime', ''), op_wait_time, op_exec_time)


# pylint: disable=too-many-instance-attributes
class ComputeRepositoryClient(_base_repository.BaseRepositoryClient):
    """Compute API Respository."""

    def __init__(self,
                 quota_max_calls=None,
                 quota_period=100.0,
                 use_rate_limiter=True,
                 read_only=False):
        """Constructor.

        Args:
            quota_max_calls (int): Allowed requests per <quota_period> for the
                API.
            quota_period (float): The time period to track requests over.
            use_rate_limiter (bool): Set to false to disable the use of a rate
                limiter for this service.
            read_only (bool): When set to true, disables any API calls that
                would modify a resource within the repository.
        """
        if not quota_max_calls:
            use_rate_limiter = False

        self._backend_services = None
        self._disks = None
        self._firewalls = None
        self._forwarding_rules = None
        self._global_operations = None
        self._images = None
        self._instance_group_managers = None
        self._instance_groups = None
        self._instance_templates = None
        self._instances = None
        self._networks = None
        self._projects = None
        self._region_instance_groups = None
        self._snapshots = None
        self._subnetworks = None

        super(ComputeRepositoryClient, self).__init__(
            'compute', versions=['beta', 'v1'],
            quota_max_calls=quota_max_calls,
            quota_period=quota_period,
            use_rate_limiter=use_rate_limiter,
            read_only=read_only)

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
    def disks(self):
        """Returns a _ComputeDisksRepository instance."""
        if not self._disks:
            self._disks = self._init_repository(
                _ComputeDisksRepository)
        return self._disks

    @property
    def firewalls(self):
        """Returns a _ComputeFirewallsRepository instance."""
        if not self._firewalls:
            self._firewalls = self._init_repository(
                _ComputeFirewallsRepository)
        return self._firewalls

    @property
    def forwarding_rules(self):
        """Returns a _ComputeForwardingRulesRepository instance."""
        if not self._forwarding_rules:
            self._forwarding_rules = self._init_repository(
                _ComputeForwardingRulesRepository)
        return self._forwarding_rules

    @property
    def global_operations(self):
        """Returns a _ComputeGlobalOperationsRepository instance."""
        if not self._global_operations:
            self._global_operations = self._init_repository(
                _ComputeGlobalOperationsRepository)
        return self._global_operations

    @property
    def images(self):
        """Returns a _ComputeImagesRepository instance."""
        if not self._images:
            self._images = self._init_repository(
                _ComputeImagesRepository)
        return self._images

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
    def instance_templates(self):
        """Returns a _ComputeInstanceTemplatesRepository instance."""
        if not self._instance_templates:
            self._instance_templates = self._init_repository(
                _ComputeInstanceTemplatesRepository)
        return self._instance_templates

    @property
    def instances(self):
        """Returns a _ComputeInstancesRepository instance."""
        if not self._instances:
            self._instances = self._init_repository(
                _ComputeInstancesRepository)
        return self._instances

    @property
    def networks(self):
        """Returns a _ComputeNetworksRepository instance."""
        if not self._networks:
            self._networks = self._init_repository(
                _ComputeNetworksRepository)
        return self._networks

    @property
    def projects(self):
        """Returns a _ComputeProjectsRepository instance."""
        if not self._projects:
            self._projects = self._init_repository(
                _ComputeProjectsRepository)
        return self._projects

    @property
    def region_instance_groups(self):
        """Returns a _ComputeRegionInstanceGroupsRepository instance."""
        if not self._region_instance_groups:
            self._region_instance_groups = self._init_repository(
                _ComputeRegionInstanceGroupsRepository)
        return self._region_instance_groups

    @property
    def snapshots(self):
        """Returns a _ComputeSnapshotsRepository instance."""
        if not self._snapshots:
            self._snapshots = self._init_repository(
                _ComputeSnapshotsRepository)
        return self._snapshots

    @property
    def subnetworks(self):
        """Returns a _ComputeSubnetworksRepository instance."""
        if not self._subnetworks:
            self._subnetworks = self._init_repository(
                _ComputeSubnetworksRepository)
        return self._subnetworks
    # pylint: enable=missing-return-doc, missing-return-type-doc


# pylint: enable=too-many-instance-attributes


class _ComputeBackendServicesRepository(
        repository_mixins.AggregatedListQueryMixin,
        repository_mixins.ListQueryMixin,
        _base_repository.GCPRepository):
    """Implementation of Compute Backend Services repository."""

    def __init__(self, **kwargs):
        """Constructor.

        Args:
            **kwargs (dict): The args to pass into GCPRepository.__init__()
        """
        super(_ComputeBackendServicesRepository, self).__init__(
            component='backendServices', **kwargs)


class _ComputeDisksRepository(repository_mixins.AggregatedListQueryMixin,
                              repository_mixins.ListQueryMixin,
                              _base_repository.GCPRepository):
    """Implementation of Compute Disks repository."""

    def __init__(self, **kwargs):
        """Constructor.

        Args:
            **kwargs (dict): The args to pass into GCPRepository.__init__()
        """
        super(_ComputeDisksRepository, self).__init__(
            component='disks', **kwargs)

    # Extend the base list implementation to support the required zone field.
    # pylint: disable=arguments-differ
    def list(self, resource, zone, **kwargs):
        """List disks by zone.

        Args:
            resource (str): The project to query resources for.
            zone (str): The zone of the instance group to query.
            **kwargs (dict): Additional args to pass through to the base method.

        Returns:
            iterator: An iterator over each page of results from the API.
        """
        kwargs['zone'] = zone
        return repository_mixins.ListQueryMixin.list(self, resource, **kwargs)
    # pylint: enable=arguments-differ


class _ComputeFirewallsRepository(repository_mixins.ListQueryMixin,
                                  repository_mixins.InsertResourceMixin,
                                  repository_mixins.UpdateResourceMixin,
                                  repository_mixins.DeleteResourceMixin,
                                  _base_repository.GCPRepository):
    """Implementation of Compute Firewall Rules repository."""

    def __init__(self, **kwargs):
        """Constructor.

        Args:
            **kwargs (dict): The args to pass into GCPRepository.__init__()
        """
        super(_ComputeFirewallsRepository, self).__init__(
            component='firewalls', entity_field='firewall',
            resource_path_template='{project}/global/firewalls/{firewall}',
            **kwargs)


class _ComputeForwardingRulesRepository(
        repository_mixins.AggregatedListQueryMixin,
        repository_mixins.ListQueryMixin,
        _base_repository.GCPRepository):
    """Implementation of Compute Forwarding Rules repository."""

    def __init__(self, **kwargs):
        """Constructor.

        Args:
            **kwargs (dict): The args to pass into GCPRepository.__init__()
        """
        super(_ComputeForwardingRulesRepository, self).__init__(
            component='forwardingRules', **kwargs)

    # Extend the base list implementation to support the required region field.
    # pylint: disable=arguments-differ
    def list(self, resource, region, **kwargs):
        """List instances by zone.

        Args:
            resource (str): The project to query resources for.
            region (str): The region of the forwarding rules to query.
            **kwargs (dict): Additional args to pass through to the base method.

        Returns:
            iterator: An iterator over each page of results from the API.
        """
        kwargs['region'] = region
        return repository_mixins.ListQueryMixin.list(self, resource, **kwargs)
    # pylint: enable=arguments-differ


class _ComputeGlobalOperationsRepository(repository_mixins.GetQueryMixin,
                                         _base_repository.GCPRepository):
    """Implementation of Compute Global Operations repository."""

    def __init__(self, **kwargs):
        """Constructor.

        Args:
            **kwargs (dict): The args to pass into GCPRepository.__init__()
        """
        super(_ComputeGlobalOperationsRepository, self).__init__(
            component='globalOperations', entity_field='operation', **kwargs)


class _ComputeImagesRepository(repository_mixins.GetQueryMixin,
                               repository_mixins.ListQueryMixin,
                               _base_repository.GCPRepository):
    """Implementation of Compute Images repository."""

    def __init__(self, **kwargs):
        """Constructor.

        Args:
            **kwargs (dict): The args to pass into GCPRepository.__init__()
        """
        super(_ComputeImagesRepository, self).__init__(
            component='images', entity_field='image', **kwargs)


class _ComputeInstanceGroupManagersRepository(
        repository_mixins.AggregatedListQueryMixin,
        repository_mixins.ListQueryMixin,
        _base_repository.GCPRepository):
    """Implementation of Compute Instance Group Managers repository."""

    def __init__(self, **kwargs):
        """Constructor.

        Args:
            **kwargs (dict): The args to pass into GCPRepository.__init__()
        """
        super(_ComputeInstanceGroupManagersRepository, self).__init__(
            component='instanceGroupManagers', **kwargs)


class _ComputeInstanceGroupsRepository(
        repository_mixins.AggregatedListQueryMixin,
        repository_mixins.ListQueryMixin,
        _base_repository.GCPRepository):
    """Implementation of Compute Instance Groups repository."""

    def __init__(self, **kwargs):
        """Constructor.

        Args:
           **kwargs (dict): The args to pass into GCPRepository.__init__()
        """
        super(_ComputeInstanceGroupsRepository, self).__init__(
            component='instanceGroups', **kwargs)

    def list_instances(self, resource, instance_group, zone, **kwargs):
        """List instances for instance group.

        Args:
            resource (str): The project to query resources for.
            instance_group (str): The name of the instance group to query.
            zone (str): The zone of the instance group to query.
            **kwargs (dict): Additional args to pass through to the base method.

        Returns:
            iterator: An iterator over each page of results from the API.
        """
        kwargs['instanceGroup'] = instance_group
        kwargs['zone'] = zone
        return repository_mixins.ListQueryMixin.list(
            self, resource, verb='listInstances', **kwargs)


class _ComputeInstanceTemplatesRepository(repository_mixins.ListQueryMixin,
                                          _base_repository.GCPRepository):
    """Implementation of Compute Instance Templates repository."""

    def __init__(self, **kwargs):
        """Constructor.

        Args:
            **kwargs (dict): The args to pass into GCPRepository.__init__()
        """
        super(_ComputeInstanceTemplatesRepository, self).__init__(
            component='instanceTemplates', **kwargs)


class _ComputeInstancesRepository(
        repository_mixins.AggregatedListQueryMixin,
        repository_mixins.ListQueryMixin,
        _base_repository.GCPRepository):
    """Implementation of Compute Instances repository."""

    def __init__(self, **kwargs):
        """Constructor.

        Args:
            **kwargs (dict): The args to pass into GCPRepository.__init__()
        """
        super(_ComputeInstancesRepository, self).__init__(
            component='instances', **kwargs)

    # Extend the base list implementation to support the required zone field.
    # pylint: disable=arguments-differ
    def list(self, resource, zone, **kwargs):
        """List instances by zone.

        Args:
            resource (str): The project to query resources for.
            zone (str): The zone of the instance group to query.
            **kwargs (dict): Additional args to pass through to the base method.

        Returns:
            iterator: An iterator over each page of results from the API.
        """
        kwargs['zone'] = zone
        return repository_mixins.ListQueryMixin.list(self, resource, **kwargs)
    # pylint: enable=arguments-differ


class _ComputeNetworksRepository(repository_mixins.ListQueryMixin,
                                 _base_repository.GCPRepository):
    """Implementation of Compute Networks repository."""

    def __init__(self, **kwargs):
        """Constructor.

        Args:
            **kwargs (dict): The args to pass into GCPRepository.__init__()
        """
        super(_ComputeNetworksRepository, self).__init__(
            component='networks', **kwargs)


class _ComputeProjectsRepository(repository_mixins.GetQueryMixin,
                                 _base_repository.GCPRepository):
    """Implementation of Compute Projects repository."""

    def __init__(self, **kwargs):
        """Constructor.

        Args:
            **kwargs (dict): The args to pass into GCPRepository.__init__()
        """
        super(_ComputeProjectsRepository, self).__init__(
            component='projects', **kwargs)


class _ComputeRegionInstanceGroupsRepository(repository_mixins.ListQueryMixin,
                                             _base_repository.GCPRepository):
    """Implementation of Compute Region Instance Groups repository."""

    def __init__(self, **kwargs):
        """Constructor.

        Args:
            **kwargs (dict): The args to pass into GCPRepository.__init__()
        """
        super(_ComputeRegionInstanceGroupsRepository, self).__init__(
            component='regionInstanceGroups', **kwargs)

    def list_instances(self, resource, instance_group, region, **kwargs):
        """List instances for instance group.

        Args:
            resource (str): The project to query resources for.
            instance_group (str): The name of the instance group to query.
            region (str): The region of the instance group to query.
            **kwargs (dict): Additional args to pass through to the base method.

        Returns:
            iterator: An iterator over each page of results from the API.
        """
        kwargs['instanceGroup'] = instance_group
        kwargs['region'] = region
        return repository_mixins.ListQueryMixin.list(
            self, resource, verb='listInstances', **kwargs)


class _ComputeSnapshotsRepository(repository_mixins.ListQueryMixin,
                                  _base_repository.GCPRepository):
    """Implementation of Compute Snapshots repository."""

    def __init__(self, **kwargs):
        """Constructor.

        Args:
            **kwargs (dict): The args to pass into GCPRepository.__init__()
        """
        super(_ComputeSnapshotsRepository, self).__init__(
            component='snapshots', **kwargs)


class _ComputeSubnetworksRepository(repository_mixins.AggregatedListQueryMixin,
                                    repository_mixins.ListQueryMixin,
                                    _base_repository.GCPRepository):
    """Implementation of Compute Subnetworks repository."""

    def __init__(self, **kwargs):
        """Constructor.

        Args:
            **kwargs (dict): The args to pass into GCPRepository.__init__()
        """
        super(_ComputeSubnetworksRepository, self).__init__(
            component='subnetworks', **kwargs)

    # Extend the base list implementation to support the required region field.
    # pylint: disable=arguments-differ
    def list(self, resource, region, **kwargs):
        """List subnetworks by region.

        Args:
            resource (str): The project to query resources for.
            region (str): The region of the forwarding rules to query.
            **kwargs (dict): Additional args to pass through to the base method.

        Returns:
            iterator: An iterator over each page of results from the API.
        """
        kwargs['region'] = region
        return repository_mixins.ListQueryMixin.list(self, resource, **kwargs)
    # pylint: enable=arguments-differ


# pylint: disable=too-many-public-methods
class ComputeClient(object):
    """Compute Client."""

    # Estimation of how long to initially wait for an async API to complete.
    ESTIMATED_API_COMPLETION_IN_SEC = 7

    def __init__(self, global_configs, **kwargs):
        """Initialize.

        Args:
            global_configs (dict): Forseti config.
            **kwargs (dict): The kwargs.
        """
        max_calls, quota_period = api_helpers.get_ratelimiter_config(
            global_configs, 'compute')

        # TODO: Also allow read only to be set from the global_configs.
        # Read only if either read_only or dry_run argument is True.
        read_only = (kwargs.get('read_only', False) or
                     kwargs.get('dry_run', False))

        self.repository = ComputeRepositoryClient(
            quota_max_calls=max_calls,
            quota_period=quota_period,
            read_only=read_only,
            use_rate_limiter=kwargs.get('use_rate_limiter', True))

    def get_backend_services(self, project_id):
        """Get the backend services for a project.

        Args:
            project_id (str): The project id.

        Returns:
            list: A list of backend services for this project.
        """
        paged_results = self.repository.backend_services.aggregated_list(
            project_id)
        flattened_results = _flatten_aggregated_list_results(project_id,
                                                             paged_results,
                                                             'backendServices')
        LOGGER.debug('Getting the backend services of a project, '
                     'project_id = %s, flattened_results = %s',
                     project_id, flattened_results)
        return flattened_results

    def get_disks(self, project_id, zone=None):
        """Return the list of all disks in the project.

        Args:
            project_id (str): The project id.
            zone (str): An optional zone to query, if not provided then all
                disks in all zones are returned.

        Returns:
            list: A list of disk resources for this project.
        """
        repository = self.repository.disks
        if zone:
            paged_results = repository.list(project_id, zone)
            results = _flatten_list_results(project_id, paged_results, 'items')
        else:
            paged_results = repository.aggregated_list(project_id)
            results = _flatten_aggregated_list_results(project_id,
                                                       paged_results,
                                                       'disks')
        LOGGER.debug('Getting the list of all disks in the project,'
                     ' project_id = %s, zone = %s, results = %s',
                     project_id, zone, results)
        return results

    def get_snapshots(self, project_id):
        """Return the list of all snapshots in the project.

        Args:
            project_id (str): The project id.

        Returns:
            list: A list of snapshot resources for this project.
        """

        try:
            LOGGER.debug('Getting the list of all snapshots in project: %s',
                         project_id)
            repository = self.repository.snapshots
            results = repository.list(project_id)
            return api_helpers.flatten_list_results(results, 'items')
        except (errors.HttpError, HttpLib2Error) as e:
            api_not_enabled, details = _api_not_enabled(e)
            if api_not_enabled:
                err = api_errors.ApiNotEnabledError(details, e)
            else:
                err = api_errors.ApiExecutionError(project_id, e)

            LOGGER.warn(err)
            raise err

    def get_firewall_rules(self, project_id):
        """Get the firewall rules for a given project id.

        Args:
            project_id (str): The project id.

        Returns:
            list: A list of firewall rules for this project id.
        """
        paged_results = self.repository.firewalls.list(project_id)
        flattened_results = _flatten_list_results(project_id,
                                                  paged_results,
                                                  'items')
        LOGGER.debug('Getting the firewall rules of a given project, '
                     'project_id = %s, flattened_results = %s',
                     project_id, flattened_results)
        return flattened_results

    def delete_firewall_rule(self, project_id, rule, uuid=None, blocking=False,
                             retry_count=0, timeout=0):
        """Delete a firewall rule.

        Args:
          project_id (str): The project id.
          rule (dict): The firewall rule dict to delete.
          uuid (str): An optional UUID to identify this request. If the same
              request is resent to the API, it will ignore the additional
              requests. If uuid is not set, one will be generated for the
              request.
          blocking (bool): If true, don't return until the async operation
              completes on the backend or timeout seconds pass.
          retry_count (int): If greater than 0, retry on operation timeout.
          timeout (float): If greater than 0 and blocking is True, then raise an
              exception if timeout seconds pass before the operation completes.

        Returns:
            dict: Global Operation status and info.
            https://cloud.google.com/compute/docs/reference/latest/globalOperations/get

        Raises:
            OperationTimeoutError: Raised if the operation times out.
        """
        repository = self.repository.firewalls
        if not uuid:
            uuid = uuid4()

        try:
            results = repository.delete(project_id, target=rule['name'],
                                        requestId=uuid)
            if blocking:
                results = self.wait_for_completion(project_id, results, timeout)
        except (errors.HttpError, HttpLib2Error) as e:
            LOGGER.error('Error deleting firewall rule %s: %s', rule['name'], e)
            api_not_enabled, details = _api_not_enabled(e)
            if api_not_enabled:
                raise api_errors.ApiNotEnabledError(details, e)
            raise api_errors.ApiExecutionError(project_id, e)
        except api_errors.OperationTimeoutError as e:
            LOGGER.warn(
                'Timeout deleting firewall rule %s: %s', rule['name'], e)
            if retry_count:
                retry_count -= 1
                return self.delete_firewall_rule(
                    project_id, rule, uuid, blocking, retry_count, timeout)
            else:
                raise

        LOGGER.info(
            'Deleting firewall rule %s on project %s. Rule: %s, '
            'Result: %s', rule['name'], project_id, json.dumps(rule), results)
        return results

    def insert_firewall_rule(self, project_id, rule, uuid=None, blocking=False,
                             retry_count=0, timeout=0):
        """Insert a firewall rule.

        Args:
          project_id (str): The project id.
          rule (dict): The firewall rule dict to insert.
          uuid (str): An optional UUID to identify this request. If the same
              request is resent to the API, it will ignore the additional
              requests. If uuid is not set, one will be generated for the
              request.
          blocking (bool): If true, don't return until the async operation
              completes on the backend or timeout seconds pass.
          retry_count (int): If greater than 0, retry on operation timeout.
          timeout (float): If greater than 0 and blocking is True, then raise an
              exception if timeout seconds pass before the operation completes.

        Returns:
            dict: Global Operation status and info.
            https://cloud.google.com/compute/docs/reference/latest/globalOperations/get

        Raises:
            OperationTimeoutError: Raised if the operation times out.
        """
        repository = self.repository.firewalls
        if not uuid:
            uuid = uuid4()

        try:
            results = repository.insert(project_id, data=rule, requestId=uuid)
            if blocking:
                results = self.wait_for_completion(project_id, results, timeout)
        except (errors.HttpError, HttpLib2Error) as e:
            LOGGER.error(
                'Error inserting firewall rule %s: %s', rule['name'], e)
            api_not_enabled, details = _api_not_enabled(e)
            if api_not_enabled:
                raise api_errors.ApiNotEnabledError(details, e)
            raise api_errors.ApiExecutionError(project_id, e)
        except api_errors.OperationTimeoutError as e:
            LOGGER.warn(
                'Timeout inserting firewall rule %s: %s', rule['name'], e)
            if retry_count:
                retry_count -= 1
                return self.insert_firewall_rule(
                    project_id, rule, uuid, blocking, retry_count, timeout)
            else:
                raise

        LOGGER.info(
            'Inserting firewall rule %s on project %s. Rule: %s, '
            'Result: %s', rule['name'], project_id, json.dumps(rule), results)
        return results

    def update_firewall_rule(self, project_id, rule, uuid=None, blocking=False,
                             retry_count=0, timeout=0):
        """Update a firewall rule.

        Args:
          project_id (str): The project id.
          rule (dict): The firewall rule dict to update.
          uuid (str): An optional UUID to identify this request. If the same
              request is resent to the API, it will ignore the additional
              requests. If uuid is not set, one will be generated for the
              request.
          blocking (bool): If true, don't return until the async operation
              completes on the backend or timeout seconds pass.
          retry_count (int): If greater than 0, retry on operation timeout.
          timeout (float): If greater than 0 and blocking is True, then raise an
              exception if timeout seconds pass before the operation completes.

        Returns:
            dict: Global Operation status and info.
            https://cloud.google.com/compute/docs/reference/latest/globalOperations/get

        Raises:
            OperationTimeoutError: Raised if the operation times out.
        """
        repository = self.repository.firewalls
        if not uuid:
            uuid = uuid4()

        try:
            results = repository.update(project_id, target=rule['name'],
                                        data=rule, requestId=uuid)
            if blocking:
                results = self.wait_for_completion(project_id, results, timeout)
        except (errors.HttpError, HttpLib2Error) as e:
            LOGGER.error('Error updating firewall rule %s: %s', rule['name'], e)
            api_not_enabled, details = _api_not_enabled(e)
            if api_not_enabled:
                raise api_errors.ApiNotEnabledError(details, e)
            raise api_errors.ApiExecutionError(project_id, e)
        except api_errors.OperationTimeoutError as e:
            LOGGER.warn(
                'Timeout updating firewall rule %s: %s', rule['name'], e)
            if retry_count:
                retry_count -= 1
                return self.update_firewall_rule(
                    project_id, rule, uuid, blocking, retry_count, timeout)
            else:
                raise

        LOGGER.info(
            'Updating firewall rule %s on project %s. Rule: %s, '
            'Result: %s', rule['name'], project_id, json.dumps(rule), results)
        return results

    def get_forwarding_rules(self, project_id, region=None):
        """Get the forwarding rules for a project.

        If no region name is specified, use aggregatedList() to query for
        forwarding rules in all regions.

        Args:
            project_id (str): The project id.
            region (str): The region name.

        Returns:
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
        LOGGER.debug('Getting the forwarding rules for a project, '
                     'project_id = %s, region = %s, results = %s',
                     project_id, region, results)
        return results

    def get_global_operation(self, project_id, operation_id):
        """Get the Operations Status
        Args:
            project_id (str): The project id.
            operation_id (str): The operation id.

        Returns:
            dict: Global Operation status and info.
            https://cloud.google.com/compute/docs/reference/latest/globalOperations/get

        Raises:
            ApiNotEnabledError: Returns if the api is not enabled.
            ApiExecutionError: Returns if the api is not executable.

        """
        try:
            results = self.repository.global_operations.get(
                project_id, operation_id)
            LOGGER.debug('Getting the operation status, project_id = %s,'
                         ' operation_id = %s, results = %s',
                         project_id, operation_id, results)
            return results
        except (errors.HttpError, HttpLib2Error) as e:
            api_not_enabled, details = _api_not_enabled(e)
            if api_not_enabled:
                raise api_errors.ApiNotEnabledError(details, e)
            raise api_errors.ApiExecutionError(project_id, e)

    def get_image(self, project_id, image_name):
        """Get an image from a project.

        Args:
            project_id (str): The project id.
            image_name (str): The image name to get.

        Returns:
            dict: A Compute Image resource dict.
            https://cloud.google.com/compute/docs/reference/latest/images
        """
        try:
            results = self.repository.images.get(project_id, target=image_name)
            LOGGER.debug('Getting an image from a project, project_id = %s, '
                         'image_name = %s, results = %s',
                         project_id, image_name, results)
            return results
        except (errors.HttpError, HttpLib2Error) as e:
            api_not_enabled, details = _api_not_enabled(e)
            if api_not_enabled:
                raise api_errors.ApiNotEnabledError(details, e)
            raise api_errors.ApiExecutionError(project_id, e)

    def get_images(self, project_id):
        """Get all images created in a project.

        Args:
            project_id (str): The project id.

        Returns:
            list: A list of images for this project.
        """
        paged_results = self.repository.images.list(project_id)
        flattened_results = _flatten_list_results(project_id,
                                                  paged_results,
                                                  'items')
        LOGGER.debug('Getting all images created in a project, '
                     'project_id = %s, flattened_results = %s',
                     project_id, flattened_results)
        return flattened_results

    def get_instance_group_instances(self, project_id, instance_group_name,
                                     region=None, zone=None):
        """Get the instance groups for a project.

        One and only one of zone (for zonal instance groups) and region
        (for regional instance groups) must be specified.

        Args:
            project_id (str): The project id.
            instance_group_name (str): The instance group's name.
            region (str): The regional instance group's region.
            zone (str): The zonal instance group's zone.

        Returns:
            list: instance URLs for this instance group.

        Raises:
            ValueError: invalid combination of parameters
        """
        if not bool(zone) ^ bool(region):
            err_message = ('One and only one of zone '
                           'and region must be specified.')
            LOGGER.error(err_message)
            raise ValueError(err_message)
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

        results = [
            instance_data.get('instance')
            for instance_data in _flatten_list_results(
                project_id, paged_results, 'items')
            if 'instance' in instance_data
        ]
        LOGGER.debug('Getting the instance group for a project, project_id'
                     ' = %s, instance_group_name = %s, region = %s, '
                     'zone = %s, flattened_results = %s',
                     project_id, instance_group_name, region, zone, results)

        return results

    def get_instance_group_managers(self, project_id):
        """Get the instance group managers for a project.

        Args:
            project_id (str): The project id.

        Returns:
            list: A list of instance group managers for this project.
        """
        paged_results = self.repository.instance_group_managers.aggregated_list(
            project_id)
        flattened_results = _flatten_aggregated_list_results(
            project_id, paged_results, 'instanceGroupManagers')

        LOGGER.debug('Getting the instance group managers for a project, '
                     'project_id = %s, flattened_results = %s',
                     project_id, flattened_results)

        return flattened_results

    def get_instance_groups(self, project_id, include_instance_urls=True):
        """Get the instance groups for a project.

        Args:
            project_id (str): The project id.
            include_instance_urls (bool): If true, fetch instance urls for each
                instance group and include them in the resource dictionary.

        Returns:
            list: A list of instance groups for this project.
        """
        paged_results = self.repository.instance_groups.aggregated_list(
            project_id)

        instance_groups = sorted(
            _flatten_aggregated_list_results(project_id, paged_results,
                                             'instanceGroups'),
            key=lambda d: d.get('name'))

        if include_instance_urls:
            for instance_group in instance_groups:
                # Turn zone and region URLs into a names
                zone = os.path.basename(instance_group.get('zone', ''))
                region = os.path.basename(instance_group.get('region', ''))
                instance_group['instance_urls'] = (
                    self.get_instance_group_instances(project_id,
                                                      instance_group['name'],
                                                      zone=zone,
                                                      region=region))

        LOGGER.debug('Getting the instance groups for a project, '
                     'project_id = %s, instance_groups = %s',
                     project_id, instance_groups)

        return instance_groups

    def get_instance_templates(self, project_id):
        """Get the instance templates for a project.

        Args:
            project_id (str): The project id.

        Returns:
            list: A list of instance templates for this project.
        """
        paged_results = self.repository.instance_templates.list(project_id)
        flattened_results = _flatten_list_results(project_id,
                                                  paged_results,
                                                  'items')
        LOGGER.debug('Getting the instance templates for a project, '
                     'project_id = %s, flattened_results = %s',
                     project_id, flattened_results)
        return flattened_results

    def get_instances(self, project_id, zone=None):
        """Get the instances for a project.

        Args:
            project_id (str): The project id.
            zone (str): The zone to list the instances in.

        Returns:
            list: A list of instances for this project.
        """
        repository = self.repository.instances
        if zone:
            paged_results = repository.list(project_id, zone)
            flattened_results = _flatten_list_results(project_id,
                                                      paged_results,
                                                      'items')
        else:
            paged_results = repository.aggregated_list(project_id)
            flattened_results = _flatten_aggregated_list_results(project_id,
                                                                 paged_results,
                                                                 'instances')
        LOGGER.debug('Getting the instances for a project, project_id'
                     ' = %s, flattened_results = %s',
                     project_id, flattened_results)
        return flattened_results

    def get_networks(self, project_id):
        """Get the networks list for a given project id.

        Args:
            project_id (str): The project id.

        Returns:
            list: A list of networks for this project id.
        """
        paged_results = self.repository.networks.list(project_id)
        flattened_results = _flatten_list_results(project_id,
                                                  paged_results,
                                                  'items')
        LOGGER.debug('Getting the network list for a given project,'
                     ' project_id = %s, flattened_results = %s',
                     project_id, flattened_results)
        return flattened_results

    def get_project(self, project_id):
        """Returns the specified Project resource.

        Args:
            project_id (str): The project id.

        Returns:
            dict: A Compute Project resource dict.
            https://cloud.google.com/compute/docs/reference/latest/projects/get
        """
        try:
            results = self.repository.projects.get(project_id)
            LOGGER.debug('Getting the specified project resource, project_id'
                         ' = %s, results = %s', project_id, results)
            return results
        except (errors.HttpError, HttpLib2Error) as e:
            api_not_enabled, details = _api_not_enabled(e)
            if api_not_enabled:
                raise api_errors.ApiNotEnabledError(details, e)
            raise api_errors.ApiExecutionError(project_id, e)

    def get_quota(self, project_id, metric):
        """Returns the quota for any metric

        Args:
            project_id (str): The project id.
            metric (str): The metric name of the quota needed.

        Returns:
            dict: The quota of a requested metric in a dict.

        An example return value:

            {
              "metric": "FIREWALLS",
              "limit": 100.0,
              "usage": 9.0
            }

        Raises:
            KeyError: Metric was not found in the project.
        """
        resource = self.get_project(project_id)
        quotas = resource.get('quotas', [])
        LOGGER.debug('Getting the quota for any metric, project_id = %s,'
                     ' metric = %s, quotas = %s', project_id, metric, quotas)
        for quota in quotas:
            if quota.get('metric', '') == metric:
                return quota
        err = KeyError(
            'Passed in metric, %s, was not found for project id, %s.' %
            (metric, project_id))
        LOGGER.error(err)
        raise err

    def get_firewall_quota(self, project_id):
        """Calls get_quota to request the firewall quota
        Args:
          project_id (str): The project id.

        Returns:
            dict: The quota of a requested metric in a dict.

        An example return value:

                {
                  "metric": "FIREWALLS",
                  "limit": 100.0,
                  "usage": 9.0
                }

        Raises:
            KeyError: Metric was not a firewall resource.
        """
        metric = 'FIREWALLS'
        resource = self.get_quota(project_id, metric)
        LOGGER.debug('Getting the firewall quota, project_id = %s,'
                     ' resource = %s', project_id, resource)
        return resource

    def get_subnetworks(self, project_id, region=None):
        """Return the list of all subnetworks in the project.

        Args:
            project_id (str): The project id.
            region (str): An optional region to query, if not provided then all
                subnetworks in all regions are returned.

        Returns:
            list: A list of subnetwork resources for this project.
        """
        repository = self.repository.subnetworks
        if region:
            paged_results = repository.list(project_id, region)
            flattened_results = _flatten_list_results(project_id,
                                                      paged_results,
                                                      'items')
        else:
            paged_results = repository.aggregated_list(project_id)
            flattened_results = _flatten_aggregated_list_results(project_id,
                                                                 paged_results,
                                                                 'subnetworks')
        LOGGER.debug('Getting a list of all subnetworks in the project, '
                     'project_id = %s, region = %s, flattened_results = %s',
                     project_id, region, flattened_results)
        return flattened_results

    def is_api_enabled(self, project_id):
        """Checks if the Compute API is enabled for the specified project.

        Args:
            project_id (str): The project id.

        Returns:
            bool: True if the API is enabled, else False.
        """
        try:
            result = self.repository.projects.get(project_id, fields='name')
            LOGGER.debug('Checking if Compute API is enabled, project_id = '
                         '%s, result = %s', project_id, result)
            return bool('name' in result)  # True if name, otherwise False.
        except (errors.HttpError, HttpLib2Error) as e:
            api_not_enabled, _ = _api_not_enabled(e)
            if api_not_enabled:
                return False
            raise api_errors.ApiExecutionError(project_id, e)

    def wait_for_completion(self, project_id, operation, timeout=0,
                            initial_delay=None):
        """Wait for the operation to complete.

        Args:
            project_id (str): The project id.
            operation (dict): The global operation response from an API call.
            timeout (float): The maximum time to wait for the operation to
                complete.
            initial_delay (float): The time to wait before first checking if the
                API has completed.

        Returns:
            dict: Global Operation status and info.
            https://cloud.google.com/compute/docs/reference/latest/globalOperations/get

        Raises:
            OperationTimeoutError: Raised if the operation times out.
        """
        if operation.get('status', '') == 'DONE':
            return operation

        if initial_delay is None:
            initial_delay = self.ESTIMATED_API_COMPLETION_IN_SEC

        started_timestamp = time.time()
        time.sleep(initial_delay)

        while True:
            operation_name = operation['name']
            operation = self.get_global_operation(project_id,
                                                  operation_id=operation_name)
            if operation.get('status', '') == 'DONE':
                _debug_operation_response_time(project_id, operation)
                return operation

            if timeout and time.time() - started_timestamp > timeout:
                raise api_errors.OperationTimeoutError(project_id, operation)

            time.sleep(2)
