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

# pylint: disable=line-too-long
from google.cloud.security.common.gcp_api.cloud_resource_manager import CloudResourceManagerClient
from google.cloud.security.common.gcp_type.resource import LifecycleState
from google.cloud.security.common.gcp_type.resource import Resource
from google.cloud.security.common.gcp_type.resource import ResourceType


# pylint: disable=too-few-public-methods
# TODO: Investigate improving to avoid the use of the pylint disable.
class ProjectLifecycleState(LifecycleState):
    """Project lifecycle state.

    See: https://cloud.google.com/resource-manager/reference/rest/v1/projects#LifecycleState
    """

    DELETE_REQUESTED = 'DELETE_REQUESTED'
    DELETE_IN_PROGRESS = 'DELETE_IN_PROGRESS'


class Project(Resource):
    """Project resource."""

    def __init__(self, project_id, project_number,
                 project_name=None, parent=None,
                 lifecycle_state=ProjectLifecycleState.UNSPECIFIED):
        """Initialize.

        Args:
            project_id: The project string id.
            project_number: The project number.
            project_name: The project name.
            parent: The parent Resource.
            lifecycle_state: The project's lifecycle state.
        """
        super(Project, self).__init__(
            resource_id=project_id,
            resource_type=ResourceType.PROJECT,
            resource_name=project_name,
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
        crm_client = CloudResourceManagerClient()
        project = crm_client.get_project(self.resource_id)

        return project is not None
