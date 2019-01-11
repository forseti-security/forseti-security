# Copyright 2018 The Forseti Security Authors. All rights reserved.
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
"""A Table Resource.

See: https://cloud.google.com/bigquery/docs/reference/rest/v2/tables
"""

import json

from google.cloud.forseti.common.gcp_type import resource


class TableLifecycleState(resource.LifecycleState):
    """Represents the table's LifecycleState."""
    pass


class Table(resource.Resource):
    """Table resource."""

    RESOURCE_NAME_FMT = 'bigquery_tables/%s'

    def __init__(
            self,
            table_id,
            full_name=None,
            data=None,
            name=None,
            display_name=None,
            parent=None,
            locations=None,
            lifecycle_state=TableLifecycleState.UNSPECIFIED):
        """Initialize.
        Args:
            table_id (int): The table id.
            full_name (str): The full resource name and ancestry.
            data (str): Resource representation of the table.
            name (str): The table's unique GCP name, with the
                format "bigquery_tables/{id}".
            display_name (str): The table's display name.
            locations (List[str]): Locations this table resides in. If set,
                there should be exactly one element in the list.
            parent (Resource): The parent Resource.
            lifecycle_state (LifecycleState): The lifecycle state of the
                table.
        """
        super(Table, self).__init__(
            resource_id=table_id,
            resource_type=resource.ResourceType.TABLE,
            name=name,
            display_name=display_name,
            parent=parent,
            locations=locations,
            lifecycle_state=lifecycle_state)
        self.full_name = full_name
        self.data = data

    @classmethod
    def from_json(cls, parent, json_string):
        """Create a Table from a JSON string.

        Args:
            parent (Resource): resource this table belongs to.
            json_string(str): JSON string of a table GCP API response.

        Returns:
            Table: table resource.
        """
        table_dict = json.loads(json_string)
        table_id = table_dict['id']
        return cls(
            parent=parent,
            table_id=table_id,
            full_name='{}bigquery_table/{}/'.format(parent.full_name, table_id),
            display_name=table_id,
            data=json_string,
        )
