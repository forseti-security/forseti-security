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
"""A Project Resource.

See: https://cloud.google.com/resource-manager/reference/rest/v1/projects
"""

from google.cloud.security.common.gcp_api import cloud_resource_manager as crm
from google.cloud.security.common.gcp_type import resource


# pylint: disable=too-few-public-methods
class ProjectLifecycleState(resource.LifecycleState):
    """Project lifecycle state."""

    DELETE_REQUESTED = 'DELETE_REQUESTED'
    DELETE_IN_PROGRESS = 'DELETE_IN_PROGRESS'


class Project(resource.Resource):
    """Project resource."""

    RESOURCE_NAME_FMT = 'organizations/%s'

    def __init__(
            self,
            project_id,
            project_number=None,
            name=None,
            display_name=None,
            parent=None,
            lifecycle_state=ProjectLifecycleState.UNSPECIFIED):
        """Initialize.

        Args:
            project_id: The project string id.
            project_number: The project number.
            name: The full unique GCP name, i.e. "projects/{projectId}".
            display_name: The display name.
            parent: The parent Resource.
            lifecycle_state: The project's lifecycle state.
        """
        super(Project, self).__init__(
            resource_id=project_id,
            resource_type=resource.ResourceType.PROJECT,
            name=name,
            display_name=display_name,
            parent=parent,
            lifecycle_state=lifecycle_state)
        self.project_number = project_number

    def get_project_number(self):
        """Returns the project number."""
        return self.project_number

    def exists(self):
        """Verify that the project exists.

        Returns:
            True if we can get the project from GCP, otherwise False.
        """
        crm_client = crm.CloudResourceManagerClient()
        project = crm_client.get_project(self.id)

        return project is not None
