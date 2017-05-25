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

from google.cloud.security.common.gcp_type import errors


class ResourceType(object):
    """Resource types."""

    ORGANIZATION = 'organization'
    FOLDER = 'folder'
    PROJECT = 'project'
    GROUP = 'group'
    BACKEND_SERVICE = 'backend_service'
    FORWARDING_RULE = 'forwarding_rule'
    BUCKETS_ACL = 'buckets_acl'
    CLOUDSQL_ACL = 'cloudsql_instances'
    resource_types = frozenset([
        ORGANIZATION,
        FOLDER,
        PROJECT,
        GROUP,
        FORWARDING_RULE,
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
            raise errors.InvalidResourceTypeError(
                'Invalid resource type: {}'.format(resource_type))
        return resource_type


# pylint: disable=too-few-public-methods
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
            lifecycle_state=LifecycleState.UNSPECIFIED):
        """Initialize.

        Args:
            resource_id: The resource's unique id (string) in GCP.
            resource_type: The resource type.
            name: The resource unique name,
                e.g. "<resource type>/{id}".
            display_name: The resource display name.
            parent: The parent Resource object.
            lifecycle_state: The lifecycle state of the Resource.
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
        self._lifecycle_state = lifecycle_state

    def __eq__(self, other):
        """Test equality of Resource."""
        if not isinstance(other, type(self)):
            return NotImplemented
        return (self.id == other.id and
                self.type == self.type)

    def __ne__(self, other):
        """Test inequality of Resource."""
        return not self == other

    def __hash__(self):
        """Create a hash on the resource type and id."""
        return hash((self.type, self.id))

    def __repr__(self):
        """String representation of the Resource."""
        return '{}<id={},parent={}>'.format(
            self.type, self.id, self.parent)

    @property
    def id(self):
        """Resource id."""
        return self._resource_id

    @property
    def type(self):
        """Resource type."""
        return self._resource_type

    @property
    def name(self):
        """GCP name."""
        return self._name

    @property
    def display_name(self):
        """Display name."""
        return self._display_name

    @property
    def parent(self):
        """Resource parent."""
        return self._parent

    @property
    def lifecycle_state(self):
        """Lifecycle state."""
        return self._lifecycle_state

    @abc.abstractmethod
    def exists(self):
        """Verify that the resource exists in GCP."""
        raise NotImplementedError('Implement exists() in subclass')
