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
"""A cluster Resource.

See: https://cloud.google.com/storage/docs/json_api/v1/
"""

import json

from google.cloud.forseti.common.gcp_type import resource


class ClusterLifecycleState(resource.LifecycleState):
    """Represents the cluster's LifecycleState."""
    pass


class Cluster(resource.Resource):
    """GKE Cluster resource."""

    RESOURCE_NAME_FMT = 'clusters/%s'

    def __init__(
            self,
            cluster_id,
            full_name=None,
            data=None,
            name=None,
            display_name=None,
            parent=None,
            locations=None,
            lifecycle_state=ClusterLifecycleState.UNSPECIFIED):
        """Initialize.

        Args:
            cluster_id (int): The cluster id.
            full_name (str): The full resource name and ancestry.
            data (str): Resource representation of the cluster.
            name (str): The cluster's unique GCP name, with the
                format "clusters/{id}".
            display_name (str): The cluster's display name.
            locations (List[str]): Locations this cluster resides in.
            parent (Resource): The parent Resource.
            lifecycle_state (LifecycleState): The lifecycle state of the
                cluster.
        """
        super(Cluster, self).__init__(
            resource_id=cluster_id,
            resource_type=resource.ResourceType.KE_CLUSTER,
            name=name,
            display_name=display_name,
            parent=parent,
            locations=locations,
            lifecycle_state=lifecycle_state)
        self.full_name = full_name
        self.data = data

    @classmethod
    def from_json(cls, parent, json_string):
        """Create a cluster from a JSON string.

        Args:
            parent (Resource): resource this cluster belongs to.
            json_string(str): JSON string of a cluster GCP API response.

        Returns:
            cluster: cluster resource.
        """
        cluster_dict = json.loads(json_string)

        cluster_id = cluster_dict['name']
        return cls(
            parent=parent,
            cluster_id=cluster_id,
            full_name='{}cluster/{}/'.format(parent.full_name, cluster_id),
            display_name=cluster_id,
            locations=cluster_dict['locations'],
            data=json_string,
        )
