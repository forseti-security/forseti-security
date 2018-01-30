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

"""A Kubernetes Engine Cluster object.

See: https://cloud.google.com/kubernetes-engine/docs/
"""

import json


# pylint: disable=too-many-arguments,too-many-instance-attributes
# pylint: disable=too-many-locals,missing-param-doc,missing-type-doc
# pylint: disable=invalid-name
class KeCluster(object):
    """Represents KE Cluster resource."""

    def __init__(self, project_id, name, description, initial_node_count,
                 node_config, logging_service, monitoring_service,
                 network, cluster_ipv4_cidr, addons_config, subnetwork,
                 node_pools, locations, enable_kubernetes_alpha,
                 resource_labels, label_fingerprint, legacy_abac,
                 network_policy, ip_allocation_policy,
                 master_authorized_networks_config, maintenance_policy, zone,
                 endpoint, initial_cluster_version, current_master_version,
                 current_node_version, create_time, status, status_message,
                 node_ipv4_cidr_size, instance_group_urls, current_node_count,
                 expire_time, server_config=None, raw_json=None):
        """Initialize."""

        self.project_id = project_id
        self.name = name
        self.description = description
        self.initial_node_count = initial_node_count
        self.node_config = node_config
        self.logging_service = logging_service
        self.monitoring_service = monitoring_service
        self.network = network
        self.cluster_ipv4_cidr = cluster_ipv4_cidr
        self.addons_config = addons_config
        self.subnetwork = subnetwork
        self.node_pools = node_pools
        self.locations = locations
        self.enable_kubernetes_alpha = enable_kubernetes_alpha
        self.resource_labels = resource_labels
        self.label_fingerprint = label_fingerprint
        self.legacy_abac = legacy_abac
        self.network_policy = network_policy
        self.ip_allocation_policy = ip_allocation_policy
        self.master_authorized_networks_config = (
            master_authorized_networks_config)
        self.maintenance_policy = maintenance_policy
        self.zone = zone
        self.endpoint = endpoint
        self.initial_cluster_version = initial_cluster_version
        self.current_master_version = current_master_version
        self.current_node_version = current_node_version
        self.create_time = create_time
        self.status = status
        self.status_message = status_message
        self.node_ipv4_cidr_size = node_ipv4_cidr_size
        self.instance_group_urls = instance_group_urls
        self.current_node_count = current_node_count
        self.expire_time = expire_time
        self.server_config = server_config
        self._json = raw_json

    @classmethod
    def from_dict(cls, project_id, server_config, cluster):
        """Returns a new ForwardingRule object from dict.

        Args:
            project_id (str): The project id.
            server_config (dict): The ServerConfig for the cluster's zone.
            cluster (dict): The KE Cluster resource.
        Returns:
            KeCluster: A new KeCluster object.
        """
        return cls(
            project_id=project_id,
            name=cluster.get('name'),
            description=cluster.get('description'),
            initial_node_count=cluster.get('initialNodeCount'),
            node_config=cluster.get('nodeConfig', {}),
            logging_service=cluster.get('loggingService'),
            monitoring_service=cluster.get('monitoringService'),
            network=cluster.get('network'),
            cluster_ipv4_cidr=cluster.get('clusterIpv4Cidr'),
            addons_config=cluster.get('addonsConfig', {}),
            subnetwork=cluster.get('subnetwork'),
            node_pools=cluster.get('nodePools', []),
            locations=cluster.get('locations'),
            enable_kubernetes_alpha=cluster.get('enableKubernetesAlpha', False),
            resource_labels=cluster.get('resourceLabels', {}),
            label_fingerprint=cluster.get('labelFingerprint'),
            legacy_abac=cluster.get('legacyAbac', {}),
            network_policy=cluster.get('networkPolicy', {}),
            ip_allocation_policy=cluster.get('ipAllocationPolicy', {}),
            master_authorized_networks_config=cluster.get(
                'masterAuthorizedNetworksConfig', {}),
            maintenance_policy=cluster.get('maintenancePolicy', {}),
            zone=cluster.get('zone'),
            endpoint=cluster.get('endpoint'),
            initial_cluster_version=cluster.get('initialClusterVersion'),
            current_master_version=cluster.get('currentMasterVersion'),
            current_node_version=cluster.get('currentNodeVersion'),
            create_time=cluster.get('createTime'),
            status=cluster.get('status'),
            status_message=cluster.get('statusMessage'),
            node_ipv4_cidr_size=cluster.get('nodeIpv4CidrSize'),
            instance_group_urls=cluster.get('instanceGroupUrls', []),
            current_node_count=cluster.get('currentNodeCount'),
            expire_time=cluster.get('expireTime'),
            server_config=server_config,
            raw_json=json.dumps(cluster)
        )

    @staticmethod
    def from_json(project_id, server_config, cluster):
        """Returns a new ForwardingRule object from json data.

        Args:
            project_id (str): the project id.
            server_config (str): The json string representations of the
                ServerConfig for the cluster's zone.
            cluster (str): The json string representation of the KE Cluster
                resource.
        Returns:
           KeCluster: A new KeCluster object.
        """
        cluster = json.loads(cluster)
        if server_config:
            server_config = json.loads(server_config)

        return KeCluster.from_dict(project_id, server_config, cluster)

    def __repr__(self):
        """String representation.
        Returns:
            str: Json string.
        """
        return self._json

    def __hash__(self):
        """Return hash of properties.
        Returns:
            hash: The hash of the class properties.
        """
        return hash(self._json)
