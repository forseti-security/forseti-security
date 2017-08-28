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

"""A "key" uniquely identifying a GCP resource.

Keys can be converted to and from URLs.
"""

import urlparse


class Key(object):
    """Represents a reference to a unique GCP object.

    Entities in the GCP API have a composite 'key' that can
    uniquely identify them. For instance, if a GET request for
    an object requires a project and a name, then (project, name)
    is a unique key for that object. Or, if the URL to an object
    has a path containing a project, a zone, and an object ID,
    then (project, zone, ID) forms a key to the object."""

    def __init__(self, object_kind, object_path):
        """Constructs a key given a 'path' to the object.

        Suggested usage: Specific gcp_type classes should subclass
        this and provide a 'from_args' with a fixed object_kind
        and specific kwargs for object_path. Callers (other than subclassers)
        should use 'from_args' or 'from_url' instead of calling this directly!

        Args:
            object_kind (str): The kind of resource the key represents
            object_path (dict): Description of the properties that uniquely
                                identify the object
        """
        self._object_kind = object_kind
        self._object_path = dict(object_path)

        # Turn all None into empty string. Otherwise it's too easy for
        # two keys to compare as unequal because one has zone=None while
        # the other has zone='', the two are semantically equivalent.
        for (key, val) in self._object_path.iteritems():
            if val is None:
                self._object_path[key] = ''

        self._object_path_tuple = tuple(sorted(self._object_path.items()))

    @classmethod
    def _from_url(cls, object_kind, path_component_map, url, defaults=None):
        """Constructs a key given a GCP object reference URL.

        Inter-object references in GCP APIs use URLs. These URLs are a sequence
        of key-value pairs describing the path to the resource, e.g.:
          https://www.googleapis.com/compute/v1
          /projects/foo
          /global
          /backendServices/bar
        describes a backend service named 'bar' with global scope in
        project 'foo', whereas:
          https://www.googleapis.com/compute/v1
          /projects/foo
          /zones/us-east1-a
          /instances/bar
        describes a compute instance named 'bar' in zone 'us-east1-a'
        of project 'foo'.

        Args:
            object_kind (str): The kind of resource the key represents
            path_component_map (dict): Maps components in the URL
                                       path to object_path keys. In the backend
                                       service example, this would be:
                                         {'projects': 'project_id',
                                          'backendServices': 'name'}
                                       The special component 'global'
                                       is ignored.  If a component not
                                       seen in this map is seen, this
                                       function raises an
                                       exception. The caller is
                                       responsible for checking that
                                       all required components were
                                       present.
            url (str): Resource URL
            defaults (dict): If non-None, a dictionary specifying default values
                             for object_path keys.

        Returns:
            Key: A Key instance

        Raises:
            ValueError: If the URL is invalid.
        """
        # The first two components identify the API name and version,
        # e.g. ('compute', 'v1'). Ignore those.
        path_components = urlparse.urlparse(url)[2].split('/')[3:]

        key_name = None
        object_path = dict((key, None) for key in path_component_map.values())
        if defaults:
            object_path.update(defaults)
        for path_component in path_components:
            if key_name:
                object_path[key_name] = path_component
                key_name = None
            elif path_component == 'global':
                # GCE APIs use special path 'global' to indicate that there's
                # no scope (zone, region, etc.)
                pass
            else:
                key_name = path_component_map.get(path_component)
                if not key_name:
                    raise ValueError('Unexpected key %s in %s URL %r' % (
                        path_component, object_kind, url))

        if key_name:
            raise ValueError('No value found for key %s in %s URL %r' % (
                key_name, object_kind, url))
        else:
            return cls(object_kind, object_path)

    def _path_component(self, key):
        """Retrieves a specific element from the path.

        Args:
            key (str): The component to retrieve

        Returns:
            object: The value
        """
        return self._object_path.get(key)

    def __cmp__(self, other):
        """Compare a Key with another object for sorting purposes.

        Args:
            other (object): The object to compare with

        Returns:
            int: (-1 if self < other, 0 if self == other, 1 if self > other)
        """
        # pylint: disable=protected-access
        if isinstance(other, Key):
            return (cmp(self._object_kind, other._object_kind) or
                    cmp(self._object_path_tuple, other._object_path_tuple))
        return cmp(self, other)

    def __hash__(self):
        """Hashcode for the object.

        Returns:
            int: The hash code
        """
        return hash((self._object_kind, self._object_path_tuple))

    def __repr__(self):
        """Debugging representation of the object.

        Returns:
            str: The debug string
        """
        return 'Key(%r, %r)' % (self._object_kind, self._object_path)
