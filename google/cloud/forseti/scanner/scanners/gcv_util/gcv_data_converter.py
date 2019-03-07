# Copyright 2019 The Forseti Security Authors. All rights reserved.
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

"""GCV Data Converter."""

from google.cloud.forseti.scanner.scanners.gcv_util import validator_pb2


_IAM_POLICY = 'iam_policy'
_RESOURCE = 'resource'

SUPPORTED_DATA_TYPE = frozenset([_IAM_POLICY, _RESOURCE])


CAI_RESOURCE_TYPE_MAPPING = {
    # TODO: Support non cai resource type by creating a fake cai resource type.
    # e.g. 'lien' -> 'google.SOME_RESOURCE_TYPE.Lien'
}


def _generate_ancestry_path(full_name):
    """Generate ancestry path from full_name.

    Args:
        full_name (str): Full name of the resource.

    Returns:
        str: Ancestry path.
    """
    supported_ancestors = ['organization', 'folder', 'project']
    ancestry_path = ''
    full_name_items = full_name.split('/')
    for i in range(0, len(full_name_items)-1):
        if full_name_items[i] in supported_ancestors:
            ancestry_path += full_name_items[i] + '/' + full_name_items[i+1]
            i += 1
        else:
            break


def convert_data_to_gcv_asset(resource, data_type):
    """Convert data to CAI format.

    Args:
        resource (Resource): Resource from querying the resources table.
        data_type (str): Type of the data, can either be 'resource'
            or 'iam_policy'.

    Returns:
        Asset: A GCV Asset.

    Raises:
        ValueError: if data_type is have an unexpected type.
    """
    if data_type not in SUPPORTED_DATA_TYPE:
        raise ValueError("Data type %s not supported.", data_type)

    if (not resource.cai_resource_name and
            resource.type not in CAI_RESOURCE_TYPE_MAPPING):
        raise ValueError("Resource %s not supported to use GCV scanner.",
                         resource.type)

    # Generate ancestry path that ends at project as the lowest level.
    ancestry_path = _generate_ancestry_path(resource.full_name)

    return validator_pb2.Asset(name=resource.cai_resource_name,
                               asset_type=resource.cai_resource_type,
                               ancestry_path=ancestry_path,
                               resource=resource.data)
