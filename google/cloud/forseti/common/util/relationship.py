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

"""Util for finding resource entity relationships."""

from google.cloud.forseti.common.gcp_type import resource_util
from google.cloud.forseti.services import utils


def find_ancestors(starting_resource, full_name):
    """Find the ancestors for a given resource.

    Take advantage of the full name from the data model which has
    the entire hierarchy.

    Keeping this outside of the class, because the class is mocked out during
    testing.

    Args:
        starting_resource (Resource): The GCP resource associated with the
            policy binding.  This is where we move up the resource
            hierarchy.
        full_name (str): Full name of the resource in hierarchical format.
            Example of a full_name:
            organization/88888/project/myproject/firewall/99999/

    Returns:
        list: A list of GCP resources in ascending order in the resource
        hierarchy.
    """
    ancestor_resources = [starting_resource]

    resources = utils.get_resources_from_full_name(full_name)
    for resource_type, resource_id in resources:
        if (resource_type == starting_resource.type and
                resource_id == starting_resource.id):
            continue
        new_resource = resource_util.create_resource(resource_id, resource_type)
        if new_resource:
            ancestor_resources.append(new_resource)

    return ancestor_resources
