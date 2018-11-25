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

"""Util for generic operations for Resources."""

from google.cloud.forseti.common.gcp_type import backend_service
from google.cloud.forseti.common.gcp_type import billing_account
from google.cloud.forseti.common.gcp_type import bucket
from google.cloud.forseti.common.gcp_type import cloudsql_instance
from google.cloud.forseti.common.gcp_type import ke_cluster
from google.cloud.forseti.common.gcp_type import dataset
from google.cloud.forseti.common.gcp_type import folder
from google.cloud.forseti.common.gcp_type import instance
from google.cloud.forseti.common.gcp_type import organization as org
from google.cloud.forseti.common.gcp_type import project
from google.cloud.forseti.common.gcp_type import resource
from google.cloud.forseti.services import utils

_RESOURCE_TYPE_MAP = {
    resource.ResourceType.ORGANIZATION: {
        'class': org.Organization,
        'plural': 'Organizations',
        'can_create_resource': True,
    },
    resource.ResourceType.BILLING_ACCOUNT: {
        'class': billing_account.BillingAccount,
        'plural': 'Billing Accounts',
        'can_create_resource': True,
    },
    resource.ResourceType.FOLDER: {
        'class': folder.Folder,
        'plural': 'Folders',
        'can_create_resource': True,
    },
    resource.ResourceType.PROJECT: {
        'class': project.Project,
        'plural': 'Projects',
        'can_create_resource': True,
    },
    resource.ResourceType.BACKEND_SERVICE: {
        'class': backend_service.BackendService,
        'plural': 'Backend Services',
        'can_create_resource': False,
    },
    resource.ResourceType.BUCKET: {
        'class': bucket.Bucket,
        'plural': 'Buckets',
        'can_create_resource': True,
    },
    resource.ResourceType.CLOUD_SQL_INSTANCE: {
        'class': cloudsql_instance.CloudSQLInstance,
        'plural': 'Cloud SQL Instances',
        'can_create_resource': True,
    },
    resource.ResourceType.DATASET: {
        'class': dataset.Dataset,
        'plural': 'Datasets',
        'can_create_resource': True,
    },
    resource.ResourceType.INSTANCE: {
        'class': instance.Instance,
        'plural': 'GCE Instances',
        'can_create_resource': True,
    },
    resource.ResourceType.KE_CLUSTER: {
        'class': ke_cluster.KeCluster,
        'plural': 'GKE Clusters',
        'can_create_resource': True,
    },
}


def create_resource(resource_id, resource_type, **kwargs):
    """Factory to create a certain kind of Resource.

    Args:
        resource_id (str): The resource id.
        resource_type (str): The resource type.
        **kwargs (dict): Extra args.

    Returns:
        Resource: The new Resource based on the type, if supported,
        otherwise None.
    """
    if resource_type not in _RESOURCE_TYPE_MAP:
        return None
    resource_type = _RESOURCE_TYPE_MAP[resource_type]
    if not resource_type.get('can_create_resource'):
        return None

    return resource_type.get('class')(
        resource_id, **kwargs)


def create_resource_from_json(resource_type, parent, json_string):
    """Factory to create a certain kind of Resource from JSON data.

    Args:
        resource_type (str): The resource type.
        parent (Resource): parent resource of this type.
        json_string (str): resource's JSON data.

    Returns:
        Resource: The new Resource based on the type, if supported,
        otherwise None.
    """
    if resource_type not in _RESOURCE_TYPE_MAP:
        return None
    resource_type = _RESOURCE_TYPE_MAP[resource_type]
    if not resource_type.get('can_create_resource'):
        return None

    return resource_type.get('class').from_json(parent, json_string)


def get_ancestors_from_full_name(full_name):
    """Creates a Resource for each resource in the full ancestory path.

    Args:
        full_name (str): The full resource name from the model, includes all
            parent resources in the hierarchy to the root organization.

    Returns:
        list: A list of Resource objects, from parent to base ancestor.
    """
    resource_ancestors = []
    for (resource_type, resource_id) in utils.get_resources_from_full_name(
            full_name):
        resource_ancestors.append(create_resource(resource_id, resource_type))
    return resource_ancestors


def pluralize(resource_type):
    """Determine the pluralized form of the resource type.

    Args:
        resource_type (str): The resource type for which to get its plural form.

    Returns:
        str: The pluralized version of the resource type, if supported,
        otherwise None.
    """
    if resource_type not in _RESOURCE_TYPE_MAP:
        return None

    return _RESOURCE_TYPE_MAP.get(resource_type).get('plural')


def type_from_name(resource_name):
    """Determine resource type from resource name.

    Args:
        resource_name (str): The unique resoure name, with the format
            "{resource_type}/{resource_id}".

    Returns:
        str: The resource type, if it exists, otherwise None.
    """
    if not resource_name:
        return None

    for (resource_type, metadata) in _RESOURCE_TYPE_MAP.iteritems():
        if resource_name.startswith(metadata['plural'].lower()):
            return resource_type

    return None


def cast_to_gcp_resources(resources_to_cast):
    """Get a list Resource objects from a list of dict resource descriptors

    Args:
        resources_to_cast (list): A list of resource descriptors
            as dictionaries.
            [{'resourceId': {'id': '3456', 'type': 'Project'}}
            {'resourceId': {'id': '1234', 'type': 'Organization'}}]

    Returns:
        list: A list of cast Resource objects
    """

    cast_resources = []
    for resource_to_cast in resources_to_cast:
        resource_id = resource_to_cast['resourceId']['id']
        resource_type = resource_to_cast['resourceId']['type']
        cast_resource = create_resource(resource_id, resource_type)
        cast_resources.append(cast_resource)
    return cast_resources
