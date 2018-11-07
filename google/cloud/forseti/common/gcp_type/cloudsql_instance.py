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
"""A CloudSQL Instance Resource.

See: https://cloud.google.com/sql/docs/mysql/admin-api/v1beta4/
"""

import json

from google.cloud.forseti.common.gcp_type import resource


class CloudSQLInstanceLifecycleState(resource.LifecycleState):
    """Represents the cloud_sql_instance's LifecycleState."""
    pass


class CloudSQLInstance(resource.Resource):
    """CloudSQL Instance resource."""

    RESOURCE_NAME_FMT = 'instances/%s'

    def __init__(
            self,
            instance_id,
            full_name=None,
            data=None,
            name=None,
            display_name=None,
            parent=None,
            locations=None,
            lifecycle_state=CloudSQLInstanceLifecycleState.UNSPECIFIED):
        """Initialize.

        Args:
            instance_id (str): The cloud sql instance id.
            full_name (str): The full resource name and ancestry.
            data (str): Resource representation of the cloud sql instance.
            name (str): The cloud_sql_instance's unique GCP name, with the
                format "cloud_sql_instances/{id}".
            display_name (str): The cloud sql instance's display name.
            locations (List[str]): Locations this cloud sql instance resides in.
                If set, there should be exactly one element in the list.
            parent (Resource): The parent Resource.
            lifecycle_state (LifecycleState): The lifecycle state of the
                cloud_sql_instance.
        """
        super(CloudSQLInstance, self).__init__(
            resource_id=instance_id,
            resource_type=resource.ResourceType.CLOUD_SQL_INSTANCE,
            name=name,
            display_name=display_name,
            parent=parent,
            locations=locations,
            lifecycle_state=lifecycle_state)
        self.full_name = full_name
        self.data = data

    @classmethod
    def from_json(cls, parent, json_string):
        """Create a cloud_sql_instance from a JSON string.

        Args:
            parent (Resource): resource this cloud_sql_instance belongs to.
            json_string(str): JSON string of a cloud_sql_instance GCP API
                response.

        Returns:
            CloudSQLInstance: cloud sql instance resource.
        """
        instance_dict = json.loads(json_string)

        instance_id = instance_dict['name']
        return cls(
            parent=parent,
            instance_id=instance_id,
            full_name='{}cloudsqlinstance/{}/'.format(parent.full_name,
                                                      instance_id),
            display_name=instance_id,
            locations=[instance_dict['region']],
            data=json_string,
        )
