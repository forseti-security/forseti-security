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

"""Pipeline to load GKE services into Inventory."""

from google.cloud.security.common.data_access import project_dao as proj_dao
from google.cloud.security.common.util import log_util
from google.cloud.security.common.util import parser
from google.cloud.security.inventory.pipelines import base_pipeline

LOGGER = log_util.get_logger(__name__)


class LoadGkePipeline(base_pipeline.BasePipeline):
    """Load all GKE services for all projects."""

    RESOURCE_NAME = 'gke'


    def _retrieve(self):
        """Retrieve GKE data from GCP.

        Get all the projects in the current snapshot and retrieve the
        the clusters for each project.  For each distinct zone in cluster,
        get the server config.

        server_config data will be incorporated into the cluster data as there
        is a 1:1 relationship, which saves adding another table.

        Returns:
            dict: Mapping projects with their GKE clusters:
                {project1: [clusters],
                 project2: [clusters],
                 project3: [clusters]}
        """
        projects = (
            proj_dao
            .ProjectDao(self.global_configs)
            .get_projects(self.cycle_timestamp))
        gke_services = {}
        for project in projects:
            clusters = self.safe_api_call('get_clusters', project.id)

            if clusters:
                for cluster in clusters:
                    # TODO: Cache the server_config response and only make the
                    # API call for zones that we don't have data on
                    # Check if this practically would make a difference, i.e.
                    # would users really have multiple clusters in the same zone
                    # for redundancy.
                    self_link_parts = cluster.get('selfLink').split('/')
                    zone = self_link_parts[self_link_parts.index('zones')+1]
                    server_config = self.safe_api_call(
                        'get_serverconfig', project.id, zone)
                    cluster['serverConfig'] = server_config

                gke_services[project.id] = clusters


        return gke_services
    # pylint: enable=too-many-locals, too-many-nested-blocks

    def _transform(self, resource_from_api):
        """Create an iterator of GKE services to load into database.

        Args:
            resource_from_api (dict): GKE services from GCP API, keyed by
                project id, with list of clusters as values.

            {project1: [clusters],
             project2: [clusters],
             project3: [clusters]}

            Each cluster has additional server_config data included.

        Yields:
            iterator: GKE service in a dict.
        """
        for project_id, clusters in resource_from_api.iteritems():
            for cluster in clusters:
                cluster['masterAuth'] = '<not saved in forseti inventory>'
                yield {'project_id': project_id,
                       'addons_config': parser.json_stringify(
                           cluster.get('addonsConfig')),
                       'cluster_ipv4_cidr': cluster.get('clusterIpv4Cidr'),
                       'create_time': cluster.get('createTime'),
                       'current_master_version':
                           cluster.get('currentMasterVersion'),
                       'current_node_count': cluster.get('currentNodeCount'),
                       'current_node_version':
                           cluster.get('currentNodeVersion'),
                       'endpoint': cluster.get('endpoint'),
                       'initial_cluster_version':
                           cluster.get('initialClusterVersion'),
                       'instance_group_urls': cluster.get('instanceGroupUrls'),
                       'legacy_abac': parser.json_stringify(
                           cluster.get('legacyAbac')),
                       'locations': cluster.get('locations'),
                       'logging_service': cluster.get('loggingService'),
                       'monitoring_service': cluster.get('monitoringService'),
                       'name': cluster.get('name'),
                       'network': cluster.get('network'),
                       'node_config': parser.json_stringify(
                           cluster.get('nodeConfig')),
                       'node_ipv4_cidr_size': cluster.get('nodeIpv4CidrSize'),
                       'node_pools': cluster.get('nodePools'),
                       'self_link': cluster.get('selfLink'),
                       'services_ipv4_cidr': cluster.get('servicesIpv4Cidr'),
                       'status': cluster.get('status'),
                       'subnetwork': cluster.get('subnetwork'),
                       'zone': cluster.get('zone'),
                       'server_config': parser.json_stringify(
                           cluster.get('serverConfig')),
                       'raw_cluster': parser.json_stringify(cluster)}

    def run(self):
        """Run the pipeline."""
        gke_services = self._retrieve()

        if gke_services:
            loadable_gke_services = self._transform(gke_services)
            self._load(self.RESOURCE_NAME, loadable_gke_services)

        self._get_loaded_count()
