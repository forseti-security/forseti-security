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

from google.cloud.security.common.gcp_type.folder import Folder
from google.cloud.security.common.gcp_type.organization import Organization
from google.cloud.security.common.gcp_type.project import Project
from google.cloud.security.common.gcp_type.resource import Resource
from google.cloud.security.common.gcp_type.resource import ResourceType

class ResourceUtil(object):
    """A utility for Resource operations."""

    resource_type_map = {
        'UNDEFINED': {
            'class': Resource,
            'plural': 'UNDEFINED',
            'level': 0
        },
        ResourceType.ORGANIZATION: {
            'class': Organization,
            'plural': 'Organizations',
            'level': 3
        },
        ResourceType.FOLDER: {
            'class': Folder,
            'plural': 'Folders',
            'level': 2
        },
        ResourceType.PROJECT: {
            'class': Project,
            'plural': 'Projects',
            'level': 1
        }
    }

    @classmethod
    def create_resource(cls, resource_id, resource_type):
        """Factory to create a certain kind of Resource.

        Args:
            resource_id: The resource id.
            resource_type: The resource type.

        Returns:
            The new resource based on the type.
        """
        return cls.resource_type_map.get(
            resource_type,
            cls.resource_type_map['UNDEFINED']).get('class')(
                resource_id, resource_type)

    @classmethod
    def pluralize(cls, resource_type):
        """Determine the pluralized form of the resource type.

        Args:
            resource_type: The resource type for which to get its plural form.

        Returns:
            The string pluralized version of the resource type.
        """
        return cls.resource_type_map.get(
            resource_type, cls.resource_type_map['UNDEFINED']).get('plural')
