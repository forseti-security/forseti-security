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
"""An Organization Resource.

See: https://cloud.google.com/resource-manager/reference/rest/v1/organizations
"""

from google.cloud.security.common.gcp_type import resource


class OrgLifecycleState(resource.LifecycleState):
    """Organization lifecycle state."""

    DELETED_REQUESTED = 'DELETE_REQUESTED'


class Organization(resource.Resource):
    """Organization resource."""

    RESOURCE_NAME_FMT = 'organizations/%s'

    def __init__(
            self,
            organization_id,
            name=None,
            display_name=None,
            lifecycle_state=OrgLifecycleState.UNSPECIFIED):
        """Initialize.

        Args:
            organization_id (int): The organization id.
            name (str): The organization's unique GCP name, with the
                format "organizations/{id}".
            display_name (str): The organization's display name.
            lifecycle_state (LifecycleState): The lifecycle state of the
                organization.
        """
        super(Organization, self).__init__(
            resource_id=organization_id,
            resource_type=resource.ResourceType.ORGANIZATION,
            name=name,
            display_name=display_name,
            lifecycle_state=lifecycle_state)
