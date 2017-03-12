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
"""An Organization Resource.

See: https://cloud.google.com/resource-manager/reference/rest/v1/organizations
"""

from google.cloud.security.common.gcp_api.cloud_resource_manager import CloudResourceManagerClient
from google.cloud.security.common.gcp_type.resource import LifecycleState
from google.cloud.security.common.gcp_type.resource import Resource
from google.cloud.security.common.gcp_type.resource import ResourceType


# pylint: disable=too-few-public-methods
# TODO: Investigate improving to not use the disable.
class OrgLifecycleState(LifecycleState):
    """Organization lifecycle state.

    See: https://cloud.google.com/resource-manager/reference/rest/v1/organizations#lifecyclestate
    """

    DELETED_REQUESTED = 'DELETE_REQUESTED'


class Organization(Resource):
    """Organization resource."""

    def __init__(self, organization_id, org_name=None,
                 lifecycle_state=OrgLifecycleState.UNSPECIFIED):
        """Initialize.

        Args:
            organization_id: The organization id.
            org_name: The organization's display name.
            lifecycle_state: The lifecycle state of the organization.
        """
        super(Organization, self).__init__(
            resource_id=organization_id,
            resource_type=ResourceType.ORGANIZATION,
            resource_name=org_name,
            parent=None,
            lifecycle_state=lifecycle_state)

    def exists(self):
        """Verify that the org exists.

        Returns:
            True if we can get the org from GCP, otherwise False.
        """
        crm_client = CloudResourceManagerClient()
        org = crm_client.get_organization(
            'organizations/{}'.format(self.resource_id))

        return org is not None
