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

# pylint: disable=broad-except

from google.cloud.forseti import config
from google.cloud.forseti.common.gcp_type import backend_service
from google.cloud.forseti.common.gcp_type import folder
from google.cloud.forseti.common.gcp_type import organization as org
from google.cloud.forseti.common.gcp_type import project
from google.cloud.forseti.common.gcp_type import resource
from google.cloud.forseti.common.util import class_loader_util
from google.cloud.forseti.common.util import log_util
from google.cloud.forseti.services import utils


LOGGER = log_util.get_logger(__name__)

_RESOURCE_TYPE_MAP = {
    resource.ResourceType.ORGANIZATION: {
        'class': org.Organization,
        'plural': 'Organizations',
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
}

# Temporary map of GCP types to dao, this will go away in the near future.
# pylint: disable=line-too-long
_TYPES_TO_DAO = {
    'google.cloud.forseti.common.gcp_type.project.Project': {
        'dao': 'google.cloud.forseti.common.data_access.project_dao.ProjectDao'
    },
    'google.cloud.forseti.common.gcp_type.instance.Instance': {
        'dao': 'google.cloud.forseti.common.data_access.instance_dao.InstanceDao'
    },
}
# pylint: enable=line-too-long


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


def load_all(resource_class_name):
    """Load all the resources found in the database for a resource type.

    Deprecated.

    The gcp_type class contains a property that points to its dao class,
    and the dao class has a get_all() method that retrieves all the data
    and returns the results. This is a temporary method that will go away
    with the new data access layer.

    Args:
        resource_class_name (str): The resource class name, including the
            module name (i.e. google.cloud.forseti.gcp_type.<module>.<Class>)

    Returns:
        list: The results from the database.
    """
    if not resource_class_name in _TYPES_TO_DAO:
        LOGGER.warn('No dao class associated to %s', resource_class_name)
        return None

    try:
        dao_class_name = _TYPES_TO_DAO[resource_class_name]['dao']
        LOGGER.info('Loading %s', dao_class_name)
        resource_dao = class_loader_util.load_class(dao_class_name)(
            config.FORSETI_CONFIG.root_config.common)
        LOGGER.info('Loaded %s', resource_dao)
        resources = resource_dao.get_all()
    except Exception as err:
        LOGGER.error(
            'Error getting all resources for %s due to %s',
            resource_class_name, err)
    else:
        return resources
