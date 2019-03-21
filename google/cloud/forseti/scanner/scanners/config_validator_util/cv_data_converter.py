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

"""Config Validator Data Converter."""
import json

from google.iam.v1.policy_pb2 import Policy
from google.protobuf import json_format
from google.protobuf.struct_pb2 import Value

from google.cloud.forseti.scanner.scanners.config_validator_util import (
    validator_pb2)


_IAM_POLICY = 'iam_policy'
_RESOURCE = 'resource'

SUPPORTED_DATA_TYPE = frozenset([_IAM_POLICY, _RESOURCE])


CAI_RESOURCE_TYPE_MAPPING = {
    # TODO: Support non cai resource type by creating a fake cai resource type.
    # e.g. 'lien' -> 'google.SOME_RESOURCE_TYPE.Lien'
}


def generate_ancestry_path(full_name):
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
            ancestry_path += (full_name_items[i] + '/'
                              + full_name_items[i+1] + '/')
        else:
            continue
    return ancestry_path


def convert_data_to_cv_asset(resource, data_type):
    """Convert data to CAI format.

    Args:
        resource (Resource): Resource from querying the resources table.
        data_type (str): Type of the data, can either be 'resource'
            or 'iam_policy'.

    Returns:
        Asset: A Config Validator Asset.

    Raises:
        ValueError: if data_type is have an unexpected type.
    """
    if data_type not in SUPPORTED_DATA_TYPE:
        raise ValueError("Data type %s not supported.", data_type)

    if (not resource.cai_resource_name and
            resource.type not in CAI_RESOURCE_TYPE_MAPPING):
        raise ValueError("Resource %s not supported to use Config"
                         " Validator scanner.", resource.type)

    # Generate ancestry path that ends at project as the lowest level.
    ancestry_path = generate_ancestry_path(resource.full_name)

    data = json.loads(resource.data)

    cleanup_dict(data)

    asset_resource, asset_iam_policy = Value(), Policy()

    if data_type == _IAM_POLICY:
        asset_iam_policy = json_format.ParseDict(data, Policy(),
                                                 ignore_unknown_fields=True)
    else:
        asset_resource = json_format.ParseDict(data, Value())

    return validator_pb2.Asset(name=resource.cai_resource_name,
                               asset_type=resource.cai_resource_type,
                               ancestry_path=ancestry_path,
                               resource=asset_resource,
                               iam_policy=asset_iam_policy)


def cleanup_dict(raw_dict):
    """Remove key with empty values in a dict.

    Args:
        raw_dict (dict): Dict to clean up.
    """
    for key, value in raw_dict.items():
        if value == "" or not value:
            raw_dict.pop(key)
        elif isinstance(value, list):
            for i in value:
                if isinstance(i, dict):
                    cleanup_dict(i)
        elif isinstance(value, dict):
            cleanup_dict(value)
