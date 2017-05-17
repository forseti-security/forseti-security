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

"""Pipeline to load project cloudsql data into Inventory."""

import json

from dateutil import parser as dateutil_parser

# pylint: disable=line-too-long
from google.cloud.security.common.data_access import errors as data_access_errors
from google.cloud.security.common.gcp_api import errors as api_errors
from google.cloud.security.common.util import log_util
from google.cloud.security.inventory import errors as inventory_errors
from google.cloud.security.inventory.pipelines import base_pipeline
# pylint: enable=line-too-long



LOGGER = log_util.get_logger(__name__)


class LoadProjectsCloudsqlPipeline(base_pipeline.BasePipeline):
    """Pipeline to load project buckets data into Inventory."""

    PROJECTS_RESOURCE_NAME = 'project_iam_policies'
    RESOURCE_NAME_INSTANCES = 'cloudsql_instances'
    RESOURCE_NAME_IPADDRESSES = 'cloudsql_ipaddresses'
    RESOURCE_NAME_AUTHORIZED_NETWORKS =\
        'cloudsql_ipconfiguration_authorizednetworks'




    MYSQL_DATETIME_FORMAT = '%Y-%m-%d %H:%M:%S'

    def __init__(self, cycle_timestamp, configs, sqladmin_client, dao):
        """Constructor for the data pipeline.

        Args:
            cycle_timestamp: String of timestamp, formatted as YYYYMMDDTHHMMSSZ.
            configs: Dictionary of configurations.
            gcs_client: GCS API client.
            dao: Data access object.

        Returns:
            None
        """
        super(LoadProjectsCloudsqlPipeline, self).__init__(
            cycle_timestamp, configs, sqladmin_client, dao)


    def _transform_data(self, cloudsql_instances_map):
        """Yield an iterator of loadable instances.

        Args:
            cloudsql_instnces_maps: An iterable of instances as per-project
                dictionary.
                Example: {'project_number': 11111,
                          'instances': instances_dict}

        Yields:
            An iterable of instances dictionary.
        """

        for instances_map in cloudsql_instances_map:
            instances = instances_map['instances']
            items = instances.get('items', [])
            for item in items:
                yield {
                    'project_number': instances_map['project_number'],
                    'name': item.get('name'),
                    'project': item.get('project'),
                    'backendType': item.get('backendType'),
                    'connectionName': item.get('connectionName'),
                    'currentDiskSize': int(item.get('currentDiskSize', 0)),
                    'databaseVersion': item.get('databaseVersion'),
                    'failoverReplica_available':\
                         item.get('failoverReplica', {}).get('available'),
                    'failoverReplica_name':\
                         item.get('failoverReplica', {}).get('name'),
                    'instanceType': item.get('instanceType'),
                    'ipv6Address': item.get('ipv6Address'),
                    'kind': item.get('kind'),
                    'masterInstanceName': item.get('masterInstanceName'),
                    'maxDiskSize': int(item.get('maxDiskSize', 0)),
                    'onPremisesConfiguration_hostPort':\
                         item.get('onPremisesConfiguration', {})\
                            .get('hostPort'),
                    'onPremisesConfiguration_kind':\
                         item.get('onPremisesConfiguration', {}).get('kind'),
                    'region': item.get('region'),
                    'replicaConfiguration':\
                         json.dumps(item.get('replicaConfiguration')),
                    'replicaNames': json.dumps(item.get('replicaNames')),
                    'selfLink': item.get('selfLink'),
                    'serverCaCert': json.dumps(item.get('serverCaCert')),
                    'serviceAccountEmailAddress':\
                         item.get('serviceAccountEmailAddress'),
                    'settings_activationPolicy':\
                         item.get('settings', {}).get('activationPolicy'),
                    'settings_authorizedGaeApplications':\
                         json.dumps(item.get('settings', {})\
                        .get('authorizedGaeApplications')),
                    'settings_availabilityType':\
                        item.get('settings', {}).get('availabilityType'),
                    'settings_backupConfiguration_binaryLogEnabled':\
                        item.get('settings', {})\
                            .get('backupConfiguration', {})\
                                .get('binaryLogEnabled'),
                    'settings_backupConfiguration_enabled':\
                        item.get('settings', {})\
                            .get('backupConfiguration', {}).get('enabled'),
                    'settings_backupConfiguration_kind':\
                         item.get('settings', {})\
                            .get('backupConfiguration', {}).get('kind'),
                    'settings_backupConfiguration_startTime':\
                        item.get('settings', {})\
                            .get('backupConfiguration', {}).get('startTime'),
                    'settings_crashSafeReplicationEnabled':\
                        item.get('settings', {})\
                            .get('crashSafeReplicationEnabled'),
                    'settings_dataDiskSizeGb':\
                        int(item.get('settings', {}).get('dataDiskSizeGb', 0)),
                    'settings_dataDiskType':
                        item.get('settings', {}).get('dataDiskType'),
                    'settings_databaseFlags':
                        json.dumps(item.get('settings', {})\
                            .get('databaseFlags')),
                    'settings_databaseReplicationEnabled':
                        item.get('settings', {})\
                            .get('databaseReplicationEnabled', {}),
                    'settings_ipConfiguration_ipv4Enabled':
                        item.get('settings', {}).get('ipConfiguration', {})\
                            .get('ipv4Enabled', {}),
                    'settings_ipConfiguration_requireSsl':
                        item.get('settings', {}).get('ipConfiguration', {})\
                            .get('requireSsl', {}),
                    'settings_kind': item.get('settings', {}).get('kind'),
                    'settings_labels':
                        json.dumps(item.get('settings', {}).get('labels')),
                    'settings_locationPreference_followGaeApplication':\
                        item.get('settings', {}).get('locationPreference', {})\
                            .get('followGaeApplication'),
                    'settings_locationPreference_kind':\
                        item.get('settings', {}).get('locationPreference', {})\
                            .get('kind'),
                    'settings_locationPreference_zone':\
                        item.get('settings', {}).get('locationPreference', {})\
                            .get('zone'),
                    'settings_maintenanceWindow':\
                        json.dumps(item.get('settings', {})\
                            .get('maintenanceWindow')),
                    'settings_pricingPlan':\
                        item.get('settings', {}).get('pricingPlan'),
                    'settings_replicationType':\
                        item.get('settings', {}).get('replicationType'),
                    'settings_settingsVersion':\
                        int(item.get('settings', {}).get('settingsVersion', 0)),
                    'settings_storageAutoResize':\
                        item.get('settings', {}).get('storageAutoResize'),
                    'settings_storageAutoResizeLimit':\
                        int(item.get('settings', {})\
                            .get('storageAutoResizeLimit', 0)),
                    'settings_tier': item.get('settings', {}).get('tier'),
                    'state': item.get('state'),
                    'suspensionReason': \
                        json.dumps(item.get('suspensionReason')),
                }

    def _transform_authorizednetworks(self, cloudsql_instances_map):
        """Yield an iterator of loadable authorized networks of cloudsql
        instances.

        Args:
            cloudsql_instnces_maps: An iterable of instances as per-project
                dictionary.
                Example: {'project_number': 11111,
                          'instances': instances_dict}

        Yields:
            An iterable of authorized network dictionary.
        """

        for instances_map in cloudsql_instances_map:
            instances = instances_map['instances']
            items = instances.get('items', [])
            for item in items:
                authorizednetworks = item.get('settings', {})\
                    .get('ipConfiguration', {}).get('authorizedNetworks', [{}])
                for network in authorizednetworks:
                    if network.get('expirationTime') is not None:
                        try:
                            parsed_time = dateutil_parser\
                                .parse(network.get('expirationTime'))
                            formatted_expirationtime = (
                                parsed_time\
                                    .strftime(self.MYSQL_DATETIME_FORMAT))
                        except (TypeError, ValueError, AttributeError) as e:
                            LOGGER.error(
                                'Unable to parse timeCreated' +\
                                'from authorizednetworks: %s\n%s',
                                network.get('expirationTime', ''), e)
                            formatted_expirationtime = '1972-01-01 00:00:00'
                    else:
                        formatted_expirationtime = '1972-01-01 00:00:00'

                    yield {
                        'project_number': instances_map['project_number'],
                        'instance_name': item.get('name'),
                        'kind': network.get('kind'),
                        'name': network.get('name'),
                        'value': network.get('value'),
                        'expirationTime': formatted_expirationtime
                    }

    def _transform_ipaddresses(self, cloudsql_instances_map):
        """Yield an iterator of loadable ipAddresses of cloudsql instances.

        Args:
            cloudsql_instnces_maps: An iterable of instances as per-project
                dictionary.
                Example: {'project_number': 11111,
                          'instances': instances_dict}

        Yields:
            An iterable of ipAddresses dictionary.
        """

        for instances_map in cloudsql_instances_map:
            instances = instances_map['instances']
            items = instances.get('items', [])
            for item in items:
                ipaddresses = item.get('ipAddresses', [{}])
                for ipaddress in ipaddresses:
                    if ipaddress.get('timeToRetire') is not None:
                        try:
                            parsed_time = dateutil_parser\
                                .parse(ipaddress.get('timeToRetire'))
                            formatted_timetoretire = (
                                parsed_time\
                                    .strftime(self.MYSQL_DATETIME_FORMAT))
                        except (TypeError, ValueError, AttributeError) as e:
                            LOGGER.error(
                                'Unable to parse timeCreated' +\
                                ' from ipaddresses: %s\n%s',
                                ipaddress.get('timeToRetire', ''), e)
                            formatted_timetoretire = '1972-01-01 00:00:00'
                    else:
                        formatted_timetoretire = '1972-01-01 00:00:00'

                    yield {
                        'project_number': instances_map['project_number'],
                        'instance_name': item.get('name'),
                        'ipAddress': ipaddress.get('ipAddress'),
                        'type': ipaddress.get('type'),
                        'timeToRetire': formatted_timetoretire
                    }

    # pylint: disable=arguments-differ
    def _transform(self, cloudsql_instances_map):
        """returns a dictionary of generators for a different types of resources

        Args:
            cloudsql_instnces_maps: An iterable of instances as per-project
                dictionary.
                Example: {'project_number': 11111,
                          'instances': instances_dict}

        Returns:
            A dict of iterables as a per resource type
        """

        data_dict = {}
        data_dict[self.RESOURCE_NAME_INSTANCES] = \
            self._transform_data(cloudsql_instances_map)
        data_dict[self.RESOURCE_NAME_AUTHORIZED_NETWORKS] = \
            self._transform_authorizednetworks(cloudsql_instances_map)
        data_dict[self.RESOURCE_NAME_IPADDRESSES] = \
            self._transform_ipaddresses(cloudsql_instances_map)

        return data_dict

    def _retrieve(self):
        """Retrieve the project cloudsql instances from GCP.

        Args:
            None

        Returns:
            instances_maps: List of instances as per-project dictionary.
                Example: [{project_number: project_number,
                          instances: instances_dict}]

        Raises:
            LoadDataPipelineException: An error with loading data has occurred.
        """
        # Get the projects for which we will retrieve the instances.
        try:
            project_numbers = self.dao.get_project_numbers(
                self.PROJECTS_RESOURCE_NAME, self.cycle_timestamp)
        except data_access_errors.MySQLError as e:
            raise inventory_errors.LoadDataPipelineError(e)
        # Retrieve data from GCP.

        instances_maps = []

        for project_number in project_numbers:
            try:
                instances = self.api_client.get_instances(
                    project_number)
                instances_map = {'project_number': project_number,
                                 'instances': instances}
                instances_maps.append(instances_map)
            except api_errors.ApiExecutionError as e:
                LOGGER.error(
                    'Unable to get cloudsql instances for project %s:\n%s',
                    project_number, e)
        return instances_maps

    def _get_loaded_count(self):
        """Get the count of how many of a instances has been loaded."""
        try:
            self.count = self.dao.select_record_count(
                self.RESOURCE_NAME_INSTANCES,
                self.cycle_timestamp)
        except data_access_errors.MySQLError as e:
            LOGGER.error('Unable to retrieve record count for %s_%s:\n%s',
                         self.RESOURCE_NAME_INSTANCES, self.cycle_timestamp, e)


    def run(self):
        """Runs the load buckets data pipeline."""
        instances_maps = self._retrieve()

        loadable_instances_dict = self._transform(instances_maps)

        self._load(self.RESOURCE_NAME_INSTANCES, \
                loadable_instances_dict[self.RESOURCE_NAME_INSTANCES])
        self._load(self.RESOURCE_NAME_IPADDRESSES, \
                loadable_instances_dict[self.RESOURCE_NAME_IPADDRESSES])
        self._load(self.RESOURCE_NAME_AUTHORIZED_NETWORKS, \
                loadable_instances_dict[
                    self.RESOURCE_NAME_AUTHORIZED_NETWORKS
                    ])

        self._get_loaded_count()
