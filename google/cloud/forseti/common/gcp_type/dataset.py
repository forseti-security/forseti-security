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
"""A Dataset Resource.

See: https://cloud.google.com/bigquery/docs/reference/rest/v2/datasets
"""

import json

from google.cloud.forseti.common.gcp_type import resource


class DatasetLifecycleState(resource.LifecycleState):
    """Represents the dataset's LifecycleState."""
    pass


class Dataset(resource.Resource):
    """Dataset resource."""

    RESOURCE_NAME_FMT = 'datasets/%s'

    def __init__(
            self,
            dataset_id,
            full_name=None,
            data=None,
            name=None,
            display_name=None,
            parent=None,
            locations=None,
            lifecycle_state=DatasetLifecycleState.UNSPECIFIED):
        """Initialize.

        Args:
            dataset_id (int): The dataset id.
            full_name (str): The full resource name and ancestry.
            data (str): Resource representation of the dataset.
            name (str): The dataset's unique GCP name, with the
                format "datasets/{id}".
            display_name (str): The dataset's display name.
            locations (List[str]): Locations this dataset resides in. If set,
                there should be exactly one element in the list.
            parent (Resource): The parent Resource.
            lifecycle_state (LifecycleState): The lifecycle state of the
                dataset.
        """
        super(Dataset, self).__init__(
            resource_id=dataset_id,
            resource_type=resource.ResourceType.DATASET,
            name=name,
            display_name=display_name,
            parent=parent,
            locations=locations,
            lifecycle_state=lifecycle_state)
        self.full_name = full_name
        self.data = data

    @classmethod
    def from_json(cls, parent, json_string):
        """Create a dataset from a JSON string.

        Args:
            parent (Resource): resource this dataset belongs to.
            json_string(str): JSON string of a dataset GCP API response.

        Returns:
            Dataset: dataset resource.
        """
        dataset_dict = json.loads(json_string)

        dataset_id = dataset_dict['id']
        return cls(
            parent=parent,
            dataset_id=dataset_id,
            full_name='{}dataset/{}/'.format(parent.full_name, dataset_id),
            display_name=dataset_id,
            locations=[dataset_dict['location']],
            data=json_string,
        )
