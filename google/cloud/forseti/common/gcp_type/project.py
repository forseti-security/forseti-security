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

"""A Project Resource.

See: https://cloud.google.com/resource-manager/reference/rest/v1/projects
"""

import json

from google.cloud.forseti.common.gcp_type import resource


class ProjectLifecycleState(resource.LifecycleState):
    """Project lifecycle state."""

    DELETE_REQUESTED = 'DELETE_REQUESTED'


class Project(resource.Resource):
    """Project resource."""

    RESOURCE_NAME_FMT = 'projects/%s'

    def __init__(
            self,
            project_id,
            full_name=None,
            data=None,
            project_number=None,
            name=None,
            display_name=None,
            parent=None,
            lifecycle_state=ProjectLifecycleState.UNSPECIFIED):
        """Initialize.

        Args:
            project_id (str): The project "named" id.
            full_name (str): The full resource name and ancestory.
            data (str): Resource representation of the project.
            project_number (int): The project number.
            name (str): The full unique GCP name, with the format
                "projects/{projectId}".
            display_name (str): The display name.
            parent (Resource): The parent Resource.
            lifecycle_state (LifecycleState): The project's lifecycle state.
        """
        super(Project, self).__init__(
            resource_id=project_id,
            resource_type=resource.ResourceType.PROJECT,
            name=name,
            display_name=display_name,
            parent=parent,
            lifecycle_state=lifecycle_state)
        self.project_number = project_number
        self.full_name = full_name
        self.data = data

    @classmethod
    def from_json(cls, parent, json_string):
        """Creates a project from a project JSON string.

        Args:
            parent (Resource): resource this instance belongs to. Should be
                an organization.
            json_string(str): JSON string of a instance GCP API response.

        Returns:
            Project: A new Project object.
        """
        project_dict = json.loads(json_string)
        project_id = project_dict['projectId']

        full_name = 'project/{}/'.format(project_id)
        if parent:
            full_name = '{}{}'.format(parent.full_name, full_name)

        return cls(
            project_id=project_id,
            full_name=full_name,
            name='projects/' + project_id,
            display_name=project_dict['name'],
            data=json_string,
        )

    def get_project_number(self):
        """Returns the project number.
            full_name (str)

        Returns:
            int: The project number.
        """
        return self.project_number
