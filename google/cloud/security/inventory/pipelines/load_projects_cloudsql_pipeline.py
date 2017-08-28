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

"""Pipeline to load project cloudsql data into Inventory."""

import json

from dateutil import parser as dateutil_parser

# pylint: disable=line-too-long
from google.cloud.security.common.data_access import errors as data_access_errors
from google.cloud.security.common.gcp_api import errors as api_errors
from google.cloud.security.common.util import log_util
from google.cloud.security.common.util import parser
from google.cloud.security.inventory import errors as inventory_errors
from google.cloud.security.inventory.pipelines import base_pipeline
# pylint: enable=line-too-long


LOGGER = log_util.get_logger(__name__)


class LoadProjectsCloudsqlPipeline(base_pipeline.BasePipeline):
    """Pipeline to load project CloudSql data into Inventory."""

    PROJECTS_RESOURCE_NAME = 'project_iam_policies'
    RESOURCE_NAME = 'cloudsql'
    RESOURCE_NAME_INSTANCES = 'cloudsql_instances'
    RESOURCE_NAME_IPADDRESSES = 'cloudsql_ipaddresses'
    RESOURCE_NAME_AUTHORIZEDNETWORKS = (  # pylint: disable=invalid-name
        'cloudsql_ipconfiguration_authorizednetworks')

    MYSQL_DATETIME_FORMAT = '%Y-%m-%d %H:%M:%S'

    @staticmethod
    def _transform_data(cloudsql_instances_map):
        """Yield an iterator of loadable instances.

        Args:
            cloudsql_instances_map (iterable): Instances as per-project
                dictionary.
                Example: {'project_number': 11111,
                          'instances': instances_dict}

        Yields:
            iterable: cloudsql, as a per-cloudsql dictionary.
        """

        for instances_map in cloudsql_instances_map:
            instances = instances_map['instances']
            for item in instances:
                yield {
                    'project_number': instances_map['project_number'],
                    'name': item.get('name'),
                    'project': item.get('project'),
                    'backend_type': item.get('backendType'),
                    'connection_name': item.get('connectionName'),
                    'current_disk_size': int(item.get('currentDiskSize', 0)),
                    'database_version': item.get('databaseVersion'),
                    'failover_replica_available':\
                         item.get('failoverReplica', {}).get('available'),
                    'failover_replica_name':\
                         item.get('failoverReplica', {}).get('name'),
                    'instance_type': item.get('instanceType'),
                    'ipv6_address': item.get('ipv6Address'),
                    'kind': item.get('kind'),
                    'master_instance_name': item.get('masterInstanceName'),
                    'max_disk_size': int(item.get('maxDiskSize', 0)),
                    'on_premises_configuration_host_port':\
                         item.get('onPremisesConfiguration', {})\
                            .get('hostPort'),
                    'on_premises_configuration_kind':\
                         item.get('onPremisesConfiguration', {}).get('kind'),
                    'region': item.get('region'),
                    'replica_configuration':\
                         json.dumps(item.get('replicaConfiguration')),
                    'replica_names': json.dumps(item.get('replicaNames')),
                    'self_link': item.get('selfLink'),
                    'server_ca_cert': json.dumps(item.get('serverCaCert')),
                    'service_account_email_address':\
                         item.get('serviceAccountEmailAddress'),
                    'settings_activation_policy':\
                         item.get('settings', {}).get('activationPolicy'),
                    'settings_authorized_gae_applications':\
                         json.dumps(item.get('settings', {})\
                        .get('authorizedGaeApplications')),
                    'settings_availability_type':\
                        item.get('settings', {}).get('availabilityType'),
                    'settings_backup_configuration_binary_log_enabled':\
                        item.get('settings', {})\
                            .get('backupConfiguration', {})\
                                .get('binaryLogEnabled'),
                    'settings_backup_configuration_enabled':\
                        item.get('settings', {})\
                            .get('backupConfiguration', {}).get('enabled'),
                    'settings_backup_configuration_kind':\
                         item.get('settings', {})\
                            .get('backupConfiguration', {}).get('kind'),
                    'settings_backup_configuration_start_time':\
                        item.get('settings', {})\
                            .get('backupConfiguration', {}).get('startTime'),
                    'settings_crash_safe_replication_enabled':\
                        item.get('settings', {})\
                            .get('crashSafeReplicationEnabled'),
                    'settings_data_disk_size_gb':\
                        int(item.get('settings', {}).get('dataDiskSizeGb', 0)),
                    'settings_data_disk_type':
                        item.get('settings', {}).get('dataDiskType'),
                    'settings_database_flags':
                        json.dumps(item.get('settings', {})\
                            .get('databaseFlags')),
                    'settings_database_replication_enabled':
                        item.get('settings', {})\
                            .get('databaseReplicationEnabled', {}),
                    'settings_ip_configuration_ipv4_enabled':
                        item.get('settings', {}).get('ipConfiguration', {})\
                            .get('ipv4Enabled', {}),
                    'settings_ip_configuration_require_ssl':
                        item.get('settings', {}).get('ipConfiguration', {})\
                            .get('requireSsl', {}),
                    'settings_kind': item.get('settings', {}).get('kind'),
                    'settings_labels':
                        json.dumps(item.get('settings', {}).get('labels')),
                    'settings_location_preference_follow_gae_application':\
                        item.get('settings', {}).get('locationPreference', {})\
                            .get('followGaeApplication'),
                    'settings_location_preference_kind':\
                        item.get('settings', {}).get('locationPreference', {})\
                            .get('kind'),
                    'settings_location_preference_zone':\
                        item.get('settings', {}).get('locationPreference', {})\
                            .get('zone'),
                    'settings_maintenance_window':\
                        json.dumps(item.get('settings', {})\
                            .get('maintenanceWindow')),
                    'settings_pricing_plan':\
                        item.get('settings', {}).get('pricingPlan'),
                    'settings_replication_type':\
                        item.get('settings', {}).get('replicationType'),
                    'settings_settings_version':\
                        int(item.get('settings', {}).get('settingsVersion', 0)),
                    'settings_storage_auto_resize':\
                        item.get('settings', {}).get('storageAutoResize'),
                    'settings_storage_auto_resize_limit':\
                        int(item.get('settings', {})\
                            .get('storageAutoResizeLimit', 0)),
                    'settings_tier': item.get('settings', {}).get('tier'),
                    'state': item.get('state'),
                    'suspension_reason': \
                        json.dumps(item.get('suspensionReason')),
                    'raw_cloudsql_instance': parser.json_stringify(item)
                }

    def _transform_authorizednetworks(self, cloudsql_instances_map):
        """Yield an iterator of loadable authorized networks of cloudsql
        instances.

        Args:
            cloudsql_instances_map (iterable): instances as per-project
                dictionary.
                Example: {'project_number': 11111,
                          'instances': instances_dict}

        Yields:
            iterable: authorized network dictionary.
        """

        for instances_map in cloudsql_instances_map:
            instances = instances_map['instances']
            for item in instances:
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
                        'expiration_time': formatted_expirationtime
                    }

    def _transform_ipaddresses(self, cloudsql_instances_map):
        """Yield an iterator of loadable ipAddresses of cloudsql instances.

        Args:
            cloudsql_instances_map (iterable): Instances as per-project
                dictionary.
                Example: {'project_number': 11111,
                          'instances': instances_dict}

        Yields:
            iterable: ipAddresses dictionary.
        """

        for instances_map in cloudsql_instances_map:
            instances = instances_map['instances']
            for item in instances:
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
                        'ip_address': ipaddress.get('ipAddress'),
                        'type': ipaddress.get('type'),
                        'time_to_retire': formatted_timetoretire
                    }

    # pylint: disable=arguments-differ
    def _transform(self, cloudsql_instances_map):
        """returns a dictionary of generators for a different types of resources

        Args:
            cloudsql_instances_map (iterable): instances as per-project
                dictionary.
                Example: {'project_number': 11111,
                          'instances': instances_dict}

        Returns:
            dict: iterables as a per resource type
        """

        data_dict = {}
        data_dict[self.RESOURCE_NAME_INSTANCES] = \
            self._transform_data(cloudsql_instances_map)
        data_dict[self.RESOURCE_NAME_AUTHORIZEDNETWORKS] = \
            self._transform_authorizednetworks(cloudsql_instances_map)
        data_dict[self.RESOURCE_NAME_IPADDRESSES] = \
            self._transform_ipaddresses(cloudsql_instances_map)

        return data_dict

    def _retrieve(self):
        """Retrieve the project cloudsql instances from GCP.

        Returns:
            list: Instances as per-project dictionary.
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

        instances_maps = []
        for project_number in project_numbers:
            instances = self.safe_api_call('get_instances', project_number)
            if instances:
                instances_map = {'project_number': project_number,
                                 'instances': instances}
                instances_maps.append(instances_map)
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
        """Runs the load Cloudsql data pipeline."""
        instances_maps = self._retrieve()
        loadable_instances_dict = self._transform(instances_maps)

        self._load(self.RESOURCE_NAME_INSTANCES, \
                loadable_instances_dict[self.RESOURCE_NAME_INSTANCES])
        self._load(self.RESOURCE_NAME_IPADDRESSES, \
                loadable_instances_dict[self.RESOURCE_NAME_IPADDRESSES])
        self._load(self.RESOURCE_NAME_AUTHORIZEDNETWORKS, \
                loadable_instances_dict[
                    self.RESOURCE_NAME_AUTHORIZEDNETWORKS
                    ])
        self._get_loaded_count()
