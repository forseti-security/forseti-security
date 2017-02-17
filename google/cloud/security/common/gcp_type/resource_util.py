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
        ResourceType.ORGANIZATION: {
            'class': Organization,
            'level': 3
        },
        ResourceType.FOLDER: {
            'class': Folder,
            'level': 2
        },
        ResourceType.PROJECT: {
            'class': Project,
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
            resource_type, Resource).get('class')(
            resource_id, resource_type)
