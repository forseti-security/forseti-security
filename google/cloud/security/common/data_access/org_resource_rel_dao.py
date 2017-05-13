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

"""DAO for organization resource entity relationships."""

from google.cloud.security.common.data_access import folder_dao
from google.cloud.security.common.data_access import organization_dao
from google.cloud.security.common.data_access import project_dao
from google.cloud.security.common.gcp_type import resource


class OrgResourceRelDao(object):
    """DAO for organization resource entity relationships."""

    def __init__(self):
        """Initialize."""
        # Map the org resource type to the appropriate dao class
        self._resource_db_lookup = {
            resource.ResourceType.ORGANIZATION: {
                'dao': organization_dao.OrganizationDao(),
                'get': 'get_organization',
            },
            resource.ResourceType.FOLDER: {
                'dao': folder_dao.FolderDao(),
                'get': 'get_folder',
            },
            resource.ResourceType.PROJECT: {
                'dao': project_dao.ProjectDao(),
                'get': 'get_project',
            }
        }

    def find_ancestors(self, resource, snapshot_timestamp=None):
        """Find ancestors of a particular resource.

        Args:
            resource: A Resource.
            snapshot_timestamp: The timestamp to use for data lookup.

        Returns:
            A list of ancestors, starting with the closest ancestor.
        """
        # TODO: handle case where snapshot is None

        ancestors = []
        curr_resource = resource

        while curr_resource is not None:
            parent_resource = None

            if (curr_resource.parent and
                curr_resource.parent.type and
                curr_resource.parent.id):
                resource_lookup = self._resource_db_lookup.get(
                    curr_resource.parent.type, {})

                # No dao object for the parent resource, so quit
                if not resource_lookup.get('dao'):
                    break

                # Invoke the dao.get_*() method, to get the parent resource
                parent_resource = getattr(
                    resource_lookup.get('dao'),
                    resource_lookup.get('get'))(
                        curr_resource.parent.id, snapshot_timestamp)

            if parent_resource:
                ancestors.append(parent_resource)
            curr_resource = parent_resource

        return ancestors
