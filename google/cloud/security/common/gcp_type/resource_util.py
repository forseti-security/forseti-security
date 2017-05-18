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
"""Util for generic operations for Resources."""

from google.cloud.security.common.gcp_type import folder
from google.cloud.security.common.gcp_type import organization as org
from google.cloud.security.common.gcp_type import project
from google.cloud.security.common.gcp_type import resource


_RESOURCE_TYPE_MAP = {
    resource.ResourceType.ORGANIZATION: {
        'class': org.Organization,
        'plural': 'Organizations',
    },
    resource.ResourceType.FOLDER: {
        'class': folder.Folder,
        'plural': 'Folders',
    },
    resource.ResourceType.PROJECT: {
        'class': project.Project,
        'plural': 'Projects',
    },
}

def create_resource(resource_id, resource_type, **kwargs):
    """Factory to create a certain kind of Resource.

    Args:
        resource_id: The resource id.
        resource_type: The resource type.
        kwargs: Extra args.

    Returns:
        The new Resource based on the type, if supported, otherwise None.
    """
    if resource_type not in _RESOURCE_TYPE_MAP:
        return None

    return _RESOURCE_TYPE_MAP.get(resource_type).get('class')(
        resource_id, **kwargs)

def pluralize(resource_type):
    """Determine the pluralized form of the resource type.

    Args:
        resource_type: The resource type for which to get its plural form.

    Returns:
        The string pluralized version of the resource type, if supported,
        otherwise None.
    """
    if resource_type not in _RESOURCE_TYPE_MAP:
        return None

    return _RESOURCE_TYPE_MAP.get(resource_type).get('plural')

def type_from_name(resource_name):
    """Determine resource type from resource name.

    Args:
        resource_name: The unique resoure name, in the form of
            <resource_type>/<resource_id>.

    Returns:
        The resource type, if it exists, otherwise None.
    """
    if not resource_name:
        return None

    for (resource_type, metadata) in _RESOURCE_TYPE_MAP.iteritems():
        if resource_name.startswith(metadata['plural'].lower()):
            return resource_type

    return None
