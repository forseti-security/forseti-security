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

from google.cloud.forseti.common.gcp_type import resource


# pylint: disable=too-many-arguments,too-many-instance-attributes
# pylint: disable=too-many-locals,missing-param-doc,missing-type-doc
# pylint: disable=invalid-name
class KeCluster(resource.Resource):
    """Represents KE Cluster resource."""

    def __init__(self, cluster_id, parent=None, full_name=None, locations=None,
                 description=None, initial_node_count=None, node_config=None,
                 logging_service=None, monitoring_service=None, network=None,
                 cluster_ipv4_cidr=None, addons_config=None,
                 subnetwork=None, node_pools=None,
                 enable_kubernetes_alpha=None, resource_labels=None,
                 label_fingerprint=None, legacy_abac=None, network_policy=None,
                 ip_allocation_policy=None,
                 master_authorized_networks_config=None,
                 maintenance_policy=None, endpoint=None,
                 initial_cluster_version=None, current_master_version=None,
                 current_node_version=None, create_time=None, status=None,
                 status_message=None,
                 node_ipv4_cidr_size=None, instance_group_urls=None,
                 current_node_count=None,
                 expire_time=None, server_config=None,
                 data=None):
        """Initialize."""
        super(KeCluster, self).__init__(
            resource_id=cluster_id,
            resource_type=resource.ResourceType.KE_CLUSTER,
            name=cluster_id,
            display_name=cluster_id,
            parent=parent,
            locations=locations)
        self.full_name = full_name
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
        self.enable_kubernetes_alpha = enable_kubernetes_alpha
        self.resource_labels = resource_labels
        self.label_fingerprint = label_fingerprint
        self.legacy_abac = legacy_abac
        self.network_policy = network_policy
        self.ip_allocation_policy = ip_allocation_policy
        self.master_authorized_networks_config = (
            master_authorized_networks_config)
        self.maintenance_policy = maintenance_policy
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
        self.data = data
        self._dict = None

    @classmethod
    def from_json(cls, parent, json_string):
        """Returns a new ForwardingRule object from json data.

        Args:
            parent (Resource): resource this cluster belongs to.
            json_string(str): JSON string of a cluster GCP API response.

        Returns:
           KeCluster: A new KeCluster object.
        """

        cluster_dict = json.loads(json_string)
        cluster_id = cluster_dict['name']

        return cls(
            cluster_id=cluster_id,
            parent=parent,
            full_name='{}kubernetes_cluster/{}/'.format(parent.full_name,
                                                        cluster_id),
            locations=cluster_dict.get('locations'),
            description=cluster_dict.get('description'),
            initial_node_count=cluster_dict.get('initialNodeCount'),
            node_config=cluster_dict.get('nodeConfig', {}),
            logging_service=cluster_dict.get('loggingService'),
            monitoring_service=cluster_dict.get('monitoringService'),
            network=cluster_dict.get('network'),
            cluster_ipv4_cidr=cluster_dict.get('clusterIpv4Cidr'),
            addons_config=cluster_dict.get('addonsConfig', {}),
            subnetwork=cluster_dict.get('subnetwork'),
            node_pools=cluster_dict.get('nodePools', []),
            enable_kubernetes_alpha=cluster_dict.get('enableKubernetesAlpha',
                                                     False),
            resource_labels=cluster_dict.get('resourceLabels', {}),
            label_fingerprint=cluster_dict.get('labelFingerprint'),
            legacy_abac=cluster_dict.get('legacyAbac', {}),
            network_policy=cluster_dict.get('networkPolicy', {}),
            ip_allocation_policy=cluster_dict.get('ipAllocationPolicy', {}),
            master_authorized_networks_config=cluster_dict.get(
                'masterAuthorizedNetworksConfig', {}),
            maintenance_policy=cluster_dict.get('maintenancePolicy', {}),
            endpoint=cluster_dict.get('endpoint'),
            initial_cluster_version=cluster_dict.get('initialClusterVersion'),
            current_master_version=cluster_dict.get('currentMasterVersion'),
            current_node_version=cluster_dict.get('currentNodeVersion'),
            create_time=cluster_dict.get('createTime'),
            status=cluster_dict.get('status'),
            status_message=cluster_dict.get('statusMessage'),
            node_ipv4_cidr_size=cluster_dict.get('nodeIpv4CidrSize'),
            instance_group_urls=cluster_dict.get('instanceGroupUrls', []),
            current_node_count=cluster_dict.get('currentNodeCount'),
            expire_time=cluster_dict.get('expireTime'),
            data=json.dumps(cluster_dict),
        )

    @property
    def as_dict(self):
        """Return the dictionary representation of the cluster.

        Returns:
            dict: deserialized json object

        """
        if self._dict is None:
            self._dict = json.loads(self.data)

        return self._dict
