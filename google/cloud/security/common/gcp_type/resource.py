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
"""GCP Resource.

For now, this only represents Organization resources. In the future, we may
need to separate the classes depending on implementation.
"""

import abc

from google.cloud.security.common.gcp_type.errors import InvalidResourceTypeError


class ResourceType(object):
    """Resource types."""

    ORGANIZATION = 'organization'
    FOLDER = 'folder'
    PROJECT = 'project'
    resource_types = frozenset([
        ORGANIZATION,
        FOLDER,
        PROJECT
    ])

    @classmethod
    def verify(cls, resource_type):
        """Verify if the resource type is recognized.

        Args:
            resource_type: The string resource type.

        Returns:
            The resource type if it is recognized in the resource_types.

        Raises:
            InvalidResourceTypeError if resource type is not recognized.
        """
        if resource_type not in cls.resource_types:
            raise InvalidResourceTypeError(
                'Invalid resource type: {}'.format(resource_type))
        return resource_type


# pylint: disable=too-few-public-methods
# TODO: Look into improving to prevent the pylint disable.
class LifecycleState(object):
    """Resource lifecycle state."""

    ACTIVE = 'ACTIVE'
    DELETED = 'DELETED'
    UNSPECIFIED = 'LIFECYCLE_STATE_UNSPECIFIED'


class Resource(object):
    """Represents a GCP resource."""
    __metaclass__ = abc.ABCMeta

    def __init__(self, resource_id, resource_type,
                 resource_name=None, parent=None,
                 lifecycle_state=LifecycleState.UNSPECIFIED):
        """Initialize.

        Args:
            resource_id: The resource id (string).
            resource_type: The resource type.
            resource_name: The resource name.
            parent: The parent Resource object.
            lifecycle_state: The lifecycle state of the Resource.
        """
        self.resource_id = str(resource_id)
        self.resource_name = resource_name
        self.resource_type = resource_type
        self.parent = parent
        self.lifecycle_state = lifecycle_state

    def __eq__(self, other):
        """Test equality of Resource."""
        if not isinstance(other, type(self)):
            return NotImplemented
        return (self.resource_id == other.resource_id and
                self.resource_type == self.resource_type)

    def __ne__(self, other):
        """Test inequality of Resource."""
        return not self == other

    def __hash__(self):
        """Create a hash on the resource type and id."""
        return hash((self.resource_type, self.resource_id))

    def __repr__(self):
        """String representation of the Resource."""
        return 'Resource<id={},type={},parent={}>'.format(
            self.resource_id, self.resource_type, self.parent)

    def get_id(self):
        """Get resource id."""
        return self.resource_id

    def get_name(self):
        """Get resource name."""
        return self.resource_name

    def get_type(self):
        """Get resource type."""
        return self.resource_type

    def get_parent(self):
        """Get resource parent."""
        return self.parent

    def get_lifecycle_state(self):
        """Get the lifecycle state."""
        return self.lifecycle_state

    def get_ancestors(self, include_self=True):
        """Get the resource ancestors.

        Args:
            include_self: Include self in returned iterator.

        Returns:
            Iterator of Resources.
        """
        if include_self:
            curr = self
        else:
            curr = self.parent

        while curr:
            yield curr
            curr = curr.parent

    @abc.abstractmethod
    def exists(self):
        """Verify that the resource exists in GCP."""
        raise NotImplementedError('Implement exists() in subclass')
