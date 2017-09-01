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

"""Common utilities to assist in inventory pipelines."""

# pylint: disable=line-too-long
from google.cloud.security.inventory.pipeline_requirements_map import REQUIREMENTS_MAP
# pylint: enable=line-too-long


# TODO: The next editor must remove this disable and correct issues.
# pylint: disable=missing-type-doc,missing-return-type-doc
# pylint: disable=missing-param-doc


def can_inventory_groups(configs):
    """A simple function that validates required inputs to inventory groups.

    Args:
        The input flags converted to a dict.

    Returns:
        Boolean
    """
    required_execution_config_flags = [
        configs.get('domain_super_admin_email'),
        configs.get('groups_service_account_key_file')]

    return all(required_execution_config_flags)

def list_resource_pipelines():
    """Prints resources (keys) in the pipeline REQUIREMENTS_MAP (dict)."""
    resources = ', '.join(REQUIREMENTS_MAP.keys())
    print 'Available resources: %s' % resources
