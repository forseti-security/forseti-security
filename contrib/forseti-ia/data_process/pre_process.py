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


def pre_process_resource_data(resource_data_iterator,
                              resource_type,
                              selected_features):
    """Pre process resource data.

    Args:
        resource_data_iterator (list): An iterator that will iterate through
            all the resource data. Resource data is in JSON string format.
        resource_type (ResourceType): The type of the resource data.
        selected_features (list): A list of selected features, if the
            list is empty, we will include all the features.

    Returns:
        DataFrame: DataFrame table with all the resource_data.
    """

    return None
