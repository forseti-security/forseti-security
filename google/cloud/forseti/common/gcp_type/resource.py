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

"""GCP Resource.

For now, this only represents Organization resources. In the future, we may
need to separate the classes depending on implementation.
"""

import abc

from google.cloud.forseti.common.gcp_type import errors
from google.cloud.forseti.services.inventory.base import resources


class ResourceType(object):
    """Resource types."""

    # Org resources
    ORGANIZATION = resources.ResourceManagerOrganization.type()
    BILLING_ACCOUNT = resources.BillingAccount.type()
    FOLDER = resources.ResourceManagerFolder.type()
    PROJECT = resources.ResourceManagerProject.type()
    LIEN = resources.ResourceManagerLien.type()

    # Groups
    GROUP = resources.GsuiteGroup.type()

    # IAM
    SERVICE_ACCOUNT = resources.IamServiceAccount.type()
    SERVICE_ACCOUNT_KEY = resources.IamServiceAccountKey.type()

    # Compute engine
    BACKEND_SERVICE = resources.ComputeBackendService.type()
    FIREWALL_RULE = resources.ComputeFirewall.type()
    FORWARDING_RULE = resources.ComputeForwardingRule.type()
    INSTANCE = resources.ComputeInstance.type()
    INSTANCE_GROUP = resources.ComputeInstanceGroup.type()
    INSTANCE_GROUP_MANAGER = resources.ComputeInstanceGroupManager.type()
    INSTANCE_TEMPLATE = resources.ComputeInstanceTemplate.type()

    # Data storage
    BUCKET = resources.StorageBucket.type()
    CLOUD_SQL_INSTANCE = resources.CloudSqlInstance.type()
    DATASET = resources.BigqueryDataSet.type()

    # AppEngine
    APPENGINE_APP = resources.AppEngineApp.type()
    APPENGINE_INSTANCE = resources.AppEngineInstance.type()
    APPENGINE_VERSION = resources.AppEngineVersion.type()

    # Kubernetes Engine
    KE_CLUSTER = resources.KubernetesCluster.type()

    # Logging
    LOG_SINK = resources.LoggingSink.type()

    resource_types = frozenset([
        ORGANIZATION,
        BILLING_ACCOUNT,
        FOLDER,
        PROJECT,
        BUCKET,
        GROUP,
        FORWARDING_RULE,
        LIEN,
        LOG_SINK,
    ])

    @classmethod
    def verify(cls, resource_type):
        """Verify if the resource type is recognized.

        Args:
            resource_type (str): The resource type.

        Returns:
            str: The resource type if it is recognized in the resource_types.

        Raises:
            InvalidResourceTypeError: If resource type is not recognized.
        """
        if resource_type not in cls.resource_types:
            raise errors.InvalidResourceTypeError(
                'Invalid resource type: {}'.format(resource_type))
        return resource_type


class LifecycleState(object):
    """Resource lifecycle state."""

    ACTIVE = 'ACTIVE'
    DELETED = 'DELETED'
    UNSPECIFIED = 'LIFECYCLE_STATE_UNSPECIFIED'


class Resource(object):
    """Represents a GCP resource."""
    __metaclass__ = abc.ABCMeta

    def __init__(
            self,
            resource_id,
            resource_type,
            name=None,
            display_name=None,
            parent=None,
            locations=None,
            lifecycle_state=LifecycleState.UNSPECIFIED):
        """Initialize.

        Args:
            resource_id (str): The resource's unique id in GCP.
            resource_type (str): The resource type.
            name (str): The resource unique name,
                e.g. "{resource type}/{id}".
            display_name (str): The resource display name.
            locations (List[str]): Locations the resource resides in. Some
                resources have multiple locations (e.g. GKE), some support
                have a single location (e.g. GCS), while some have none
                (e.g. Project).
            parent (Resource): The parent Resource object.
            lifecycle_state (LifecycleState): The lifecycle state of the
                Resource.
        """
        self._resource_id = str(resource_id)
        self._resource_type = resource_type
        if name:
            self._name = name
        else:
            self._name = self.RESOURCE_NAME_FMT % resource_id
        self._display_name = display_name
        # TODO: maybe need assertion for parent type, e.g. assert that
        # organization has no parent, whereas projects and folders can
        # have either another folder or organization as a parent.
        self._parent = parent
        self._locations = locations
        self._lifecycle_state = lifecycle_state

    def __eq__(self, other):
        """Test equality of Resource.

        Args:
            other (object): The other object.

        Returns:
            bool: Whether the objects are equal.
        """
        if not isinstance(other, type(self)):
            return NotImplemented
        return (self.id == other.id and
                self.type == self.type)

    def __ne__(self, other):
        """Test inequality of Resource.

        Args:
            other (object): The other object.

        Returns:
            bool: Whether the objects are equal.
        """
        return not self == other

    def __hash__(self):
        """Create a hash on the resource type and id.

        Returns:
            hash: The hash of the object.
        """
        return hash((self.type, self.id))

    def __repr__(self):
        """String representation of the Resource.

        Returns:
            str: The representation.
        """
        return '{}<id={},parent={}>'.format(
            self.type, self.id, self.parent)

    @property
    def id(self):
        """Resource id.

        Returns:
            str: The id.
        """
        return self._resource_id

    @property
    def type(self):
        """Resource type.

        Returns:
            str: The type.
        """
        return self._resource_type

    @property
    def name(self):
        """GCP name.

        Returns:
            str: The name.
        """
        return self._name

    @property
    def display_name(self):
        """Display name.

        Returns:
            str: The display name.
        """
        return self._display_name

    @property
    def parent(self):
        """Resource parent.

        Returns:
            Resource: The parent.
        """
        return self._parent

    @property
    def locations(self):
        """Locations the resource resides in.

        Returns:
            List[str]: Locations the resource resides in.
        """
        return self._locations

    @property
    def lifecycle_state(self):
        """Lifecycle state.

        Returns:
            LifecycleState: The LifecycleState.
        """
        return self._lifecycle_state
