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

"""Wrapper for SQL API client."""
from googleapiclient import errors
from httplib2 import HttpLib2Error

from google.cloud.forseti.common.gcp_api import _base_repository
from google.cloud.forseti.common.gcp_api import api_helpers
from google.cloud.forseti.common.gcp_api import errors as api_errors
from google.cloud.forseti.common.gcp_api import repository_mixins
from google.cloud.forseti.common.util import logger

LOGGER = logger.get_logger(__name__)
API_NAME = 'container'


class ContainerRepositoryClient(_base_repository.BaseRepositoryClient):
    """Cloud Kubernetes Engine API Respository."""

    def __init__(self,
                 quota_max_calls=None,
                 quota_period=100.0,
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

        self._projects_locations = None
        self._projects_zones = None
        self._projects_zones_clusters = None

        super(ContainerRepositoryClient, self).__init__(
            API_NAME, versions=['v1', 'v1beta1'],
            quota_max_calls=quota_max_calls,
            quota_period=quota_period,
            use_rate_limiter=use_rate_limiter)

    # Turn off docstrings for properties.
    # pylint: disable=missing-return-doc, missing-return-type-doc
    @property
    def projects_locations(self):
        """Returns a _ContainerProjectsLocationsRepository instance."""
        if not self._projects_locations:
            self._projects_locations = self._init_repository(
                _ContainerProjectsLocationsRepository, version='v1beta1')
        return self._projects_locations

    @property
    def projects_zones(self):
        """Returns a _ContainerProjectsZonesRepository instance."""
        if not self._projects_zones:
            self._projects_zones = self._init_repository(
                _ContainerProjectsZonesRepository)
        return self._projects_zones

    @property
    def projects_zones_clusters(self):
        """Returns a _ContainerProjectsZonesClustersRepository instance."""
        if not self._projects_zones_clusters:
            self._projects_zones_clusters = self._init_repository(
                _ContainerProjectsZonesClustersRepository)
        return self._projects_zones_clusters
    # pylint: enable=missing-return-doc, missing-return-type-doc


class _ContainerProjectsLocationsRepository(
        _base_repository.GCPRepository):
    """Implementation of Container Projects.Locations repository."""

    def __init__(self, **kwargs):
        """Constructor.

        Args:
            **kwargs (dict): The args to pass into GCPRepository.__init__()
        """
        super(_ContainerProjectsLocationsRepository, self).__init__(
            component='projects.locations', **kwargs)

    def get_serverconfig(self, project_id, location, fields=None, **kwargs):
        """Get KE serverconfig for location.

        Args:
            project_id (str): The id of the project to query.
            location (str):  Name of the location to get the configuration for.
            fields (str): Fields to include in the response - partial response.
            **kwargs (dict): Optional additional arguments to pass to the query.

        Returns:
            dict: Response from the API.

        Raises:
            errors.HttpError: When attempting to get a non-existent entity.
               ex: HttpError 404 when requesting ... returned
                   "The resource '...' was not found"
        """
        name = 'projects/{}/locations/{}'.format(project_id, location)
        arguments = {
            'name': name,
            'fields': fields,
        }
        if kwargs:
            arguments.update(kwargs)
        return self.execute_query(
            verb='getServerConfig',
            verb_arguments=arguments,
        )


class _ContainerProjectsZonesRepository(
        _base_repository.GCPRepository):
    """Implementation of Container Projects.Zones repository."""

    def __init__(self, **kwargs):
        """Constructor.

        Args:
            **kwargs (dict): The args to pass into GCPRepository.__init__()
        """
        super(_ContainerProjectsZonesRepository, self).__init__(
            component='projects.zones', **kwargs)

    def get_serverconfig(self, project_id, zone, fields=None, **kwargs):
        """Get KE serverconfig for zone.

        Args:
            project_id (str): The id of the project to query.
            zone (str):  Name of the zone to get the configuration for.
            fields (str): Fields to include in the response - partial response.
            **kwargs (dict): Optional additional arguments to pass to the query.

        Returns:
            dict: Response from the API.

        Raises:
            errors.HttpError: When attempting to get a non-existent entity.
               ex: HttpError 404 when requesting ... returned
                   "The resource '...' was not found"
        """
        arguments = {
            'projectId': project_id,
            'zone': zone,
            'fields': fields,
        }
        if kwargs:
            arguments.update(kwargs)
        return self.execute_query(
            verb='getServerconfig',
            verb_arguments=arguments,
        )


class _ContainerProjectsZonesClustersRepository(
        repository_mixins.ListQueryMixin,
        _base_repository.GCPRepository):
    """Implementation of Container Projects.Zones.Clusters repository."""

    def __init__(self, **kwargs):
        """Constructor.

        Args:
            **kwargs (dict): The args to pass into GCPRepository.__init__()
        """
        super(_ContainerProjectsZonesClustersRepository, self).__init__(
            component='projects.zones.clusters', key_field='projectId',
            **kwargs)


class ContainerClient(object):
    """Cloud Kubernetes Engine Client."""

    def __init__(self, global_configs, **kwargs):
        """Initialize.

        Args:
            global_configs (dict): Global configurations.
            **kwargs (dict): The kwargs.
        """
        max_calls, quota_period = api_helpers.get_ratelimiter_config(
            global_configs, API_NAME)

        self.repository = ContainerRepositoryClient(
            quota_max_calls=max_calls,
            quota_period=quota_period,
            use_rate_limiter=kwargs.get('use_rate_limiter', True))

    def get_serverconfig(self, project_id, zone=None, location=None):
        """Gets the serverconfig for a project and zone or location.

        Requires either a zone or a location, if both are passed in, the
        location is used instead of the zone.

        Args:
            project_id (int): The project id for a GCP project.
            zone (str):  Name of the zone to get the configuration for.
            location (str): Name of the location to get the configuration for.

        Returns:
            dict: A serverconfig for a given Compute Engine zone.
            https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1beta1/ServerConfig

        An example return value:

            {
              "defaultClusterVersion": string,
              "validNodeVersions": [
                string
              ],
              "defaultImageType": string,
              "validImageTypes": [
                string
              ],
              "validMasterVersions": [
                string
              ],
            }

        Raises:
            ApiExecutionError: ApiExecutionError is raised if the call to the
                GCP API fails
            ValueError: Raised if neither zone nor location are passed in.
        """

        try:
            if location:
                return self.repository.projects_locations.get_serverconfig(
                    project_id, location=location)
            elif zone:
                return self.repository.projects_zones.get_serverconfig(
                    project_id, zone=zone)
            raise ValueError('get_serverconfig takes either zone or location, '
                             'got zone: %s, location: %s' % (zone, location))
        except (errors.HttpError, HttpLib2Error) as e:
            LOGGER.warn(api_errors.ApiExecutionError(project_id, e))
            raise api_errors.ApiExecutionError(project_id, e)

    def get_clusters(self, project_id, zone='-'):
        """Gets the clusters and their node pools for a project and zone.

        If zone is not specified, it lists clusters for all zones in the
        project.

        Args:
            project_id (int): The project id for a GCP project.
            zone (str):  Name of the zone to get the configuration for. Use
                '-' to return clusters from all zones.

        Returns:
            list: A list of Cluster dicts.
            https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.zones.clusters#Cluster

        An example return value:

            [
                {"name": "cluster-1", ...}
                {"name": "cluster-2", ...},
                {...}
            ]

        Raises:
            ApiExecutionError: ApiExecutionError is raised if the call to the
                GCP API fails
        """

        try:
            repository = self.repository.projects_zones_clusters
            results = repository.list(project_id, zone=zone)
            return api_helpers.flatten_list_results(results, 'clusters')
        except (errors.HttpError, HttpLib2Error) as e:
            LOGGER.warn(api_errors.ApiExecutionError(project_id, e))
            raise api_errors.ApiExecutionError(project_id, e)
