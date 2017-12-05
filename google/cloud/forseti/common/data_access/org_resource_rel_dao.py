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

"""DAO for organization resource entity relationships."""

from google.cloud.forseti.common.data_access import folder_dao
from google.cloud.forseti.common.data_access import organization_dao
from google.cloud.forseti.common.data_access import project_dao
from google.cloud.forseti.common.gcp_type import resource
from google.cloud.forseti.common.gcp_type import resource_util


# pylint: disable=invalid-name

class OrgResourceRelDao(object):
    """DAO for organization resource entity relationships."""

    def __init__(self, global_configs):
        """Initialize.

        Args:
            global_configs (dict): Global configurations.
        """
        # Map the org resource type to the appropriate dao class
        self._resource_db_lookup = {
            resource.ResourceType.ORGANIZATION: {
                'dao': organization_dao.OrganizationDao(global_configs),
                'get': 'get_organization',
            },
            resource.ResourceType.FOLDER: {
                'dao': folder_dao.FolderDao(global_configs),
                'get': 'get_folder',
            },
            resource.ResourceType.PROJECT: {
                'dao': project_dao.ProjectDao(global_configs),
                'get': 'get_project',
            }
        }

    def find_ancestors(self, org_resource, snapshot_timestamp=None):
        """Find ancestors of a particular resource.

        Args:
            org_resource (Resource): A Resource.
            snapshot_timestamp (str): The timestamp to use for data lookup.

        Returns:
            list: A list of Resource ancestors, starting with the
                closest (lowest-level) ancestor.
        """
        # TODO: handle case where snapshot is None

        ancestors = []
        curr_resource = org_resource

        while curr_resource is not None:
            parent_resource = None

            # If we don't have parent information for the current
            # resource, try to look it up.
            if not curr_resource.parent:
                curr_resource = self._load_resource(
                    curr_resource, snapshot_timestamp)

            if (curr_resource.parent and
                    curr_resource.parent.type and
                    curr_resource.parent.id):
                parent_resource = self._load_resource(
                    curr_resource.parent, snapshot_timestamp)

            if parent_resource:
                ancestors.append(parent_resource)
            curr_resource = parent_resource

        return ancestors

    def _load_resource(self, unloaded_resource, snapshot_timestamp):
        """Load the resource from the database.

        Args:
            unloaded_resource (Resource): The Resource to load.
            snapshot_timestamp (str): The timestamp to use for data lookup.

        Returns:
            Resource: The resource.
        """
        loaded_resource = unloaded_resource
        if not unloaded_resource:
            return unloaded_resource

        resource_lookup = self._resource_db_lookup.get(
            unloaded_resource.type, {})
        # Invoke the dao.get_*() method, to get the resource
        if resource_lookup.get('dao'):
            loaded_resource = getattr(
                resource_lookup.get('dao'),
                resource_lookup.get('get'))(
                    unloaded_resource.id, snapshot_timestamp)
        return loaded_resource


def find_ancestors_by_hierarchial_name(starting_resource,
                                       hierarchical_name):
    """Find the ancestors for a given resource.

    Take advantage of the full name from the data model which has
    the entire hierarchy.

    Keeping this outside of the class, because the class is mocked out during
    testing.

    Args:
        starting_resource (Resource): The GCP resource associated with the
            policy binding.  This is where we move up the resource
            hierarchy.
        hierarchical_name (str): Full name of the resource
            in hierarchical formmat.
            Example of a hierarchical name:
            organization/88888/project/myproject/firewall/99999/

    Returns:
        list: A list of GCP resources in ascending order in the resource
            hierarchy.
    """
    ancestor_resources = [starting_resource]

    # policy.hierarchical_name has a trailing / that needs to be removed.
    hierarchical_name = hierarchical_name.rsplit('/', 1)[0]
    hierarchical_name_parts = hierarchical_name.split('/')

    should_append_ancestor = False
    while hierarchical_name_parts:
        resource_id = hierarchical_name_parts.pop()
        resource_type = hierarchical_name_parts.pop()

        if not should_append_ancestor:
            if resource_type == starting_resource.type:
                should_append_ancestor = True
                continue

        if should_append_ancestor:
            ancestor_resources.append(
                resource_util.create_resource(resource_id, resource_type))

    return ancestor_resources
