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

""" Crawler implementation for gcp resources. """

# pylint: disable=no-self-use,unused-argument,too-many-public-methods
# pylint: disable=too-many-lines, too-many-instance-attributes

import ctypes
from functools import partial
import json

from google.cloud.forseti.common.gcp_api import errors as api_errors
from google.cloud.forseti.common.util import date_time
from google.cloud.forseti.common.util import logger
from google.cloud.forseti.common.util import string_formats

LOGGER = logger.get_logger(__name__)


def from_root_id(client, root_id):
    """Start the crawling from root if the root type is supported

    Args:
        client (object): GCP API client
        root_id (str): id of the root

    Returns:
        Resource: the root resource instance

    Raises:
        Exception: Unsupported root id
    """
    root_map = {
        'organizations': Organization.fetch,
        'projects': Project.fetch,
        'folders': Folder.fetch,
    }

    for prefix, func in root_map.iteritems():
        if root_id.startswith(prefix):
            return func(client, root_id)
    raise Exception(
        'Unsupported root id, must be one of {}'.format(
            ','.join(root_map.keys())))


def cached(field_name):
    """Decorator to perform caching

    Args:
        field_name (str): The name of the attribute to cache

    Returns:
        wrapper: Function wrapper to perform caching
    """
    field_name = '__cached_{}'.format(field_name)

    def _cached(f):
        """Args:
            f (func): function to be decorated

        Returns:
            wrapper: Function wrapper to perform caching
        """

        def wrapper(*args, **kwargs):
            """Function wrapper to perform caching

            Args:
                args: args to be passed to the function
                kwargs: kwargs to be passed to the function

            Returns:
                object: Results of executing f
            """
            if hasattr(args[0], field_name):
                return getattr(args[0], field_name)
            result = f(*args, **kwargs)
            setattr(args[0], field_name, result)
            return result

        return wrapper

    return _cached


class ResourceFactory(object):
    """ResourceFactory for visitor pattern"""

    def __init__(self, attributes):
        """Initialize

        Args:
            attributes (dict): attributes for a specific type of resource
        """
        self.attributes = attributes

    def create_new(self, data, root=False):
        """Create a new instance of a Resouce type

        Args:
            data (str): raw data
            root (Resource): root of this resource

        Returns:
            Resource: Resource instance
        """
        attrs = self.attributes
        cls = attrs['cls']
        return cls(data, root, **attrs)


class ResourceKey(object):
    """ResourceKey class"""

    def __init__(self, res_type, res_id):
        """Initialize

        Args:
            res_type (str): type of the resource
            res_id (str): id of the resource
        """
        self.res_type = res_type
        self.res_id = res_id


class Resource(object):
    """The Resource template"""

    def __init__(self, data, root=False, contains=None, **kwargs):
        """Initialize

        Args:
            data (str): raw data
            root (Resource): the root of this crawling
            contains (list): child types to crawl
            kwargs (dict): arguments
        """
        self._data = data
        self._root = root
        self._stack = None
        self._visitor = None
        self._contains = [] if contains is None else contains
        self._warning = []
        self._enabled_service_names = None
        self._timestamp = self._utcnow()
        self._inventory_key = None

    @staticmethod
    def _utcnow():
        """Wrapper for datetime.datetime.now() injection.

        Returns:
            datatime: the datetime
        """
        return date_time.get_utc_now_datetime()

    def __getitem__(self, key):
        """Get Item

        Args:
            key (str): key of this resource

        Returns:
            str: data of this resource

        Raises:
            KeyError: 'key: {}, data: {}'
        """
        try:
            return self._data[key]
        except KeyError:
            raise KeyError('key: {}, data: {}'.format(key, self._data))

    def __setitem__(self, key, value):
        """set the value of an item

        Args:
            key (str): key of this resource
            value (str): value to set on this resource
        """
        self._data[key] = value

    def set_inventory_key(self, key):
        """Set the inventory unique id for the resource.

        Args:
            key (int): The unique id for the resource from the storage.
        """
        self._inventory_key = key

    def inventory_key(self):
        """Gets the inventory key for this resource, if set.

        Returns:
            int: The unique id for the resource in storage.
        """
        return self._inventory_key

    @staticmethod
    def type():
        """Get type of this resource

        Raises:
            NotImplementedError: method not implemented
        """
        raise NotImplementedError()

    def data(self):
        """Get data on this resource

        Returns:
            str: raw data
        """
        return self._data

    def parent(self):
        """Get parent of this resource

        Returns:
            Resource: parent of this resource
        """
        if self._root:
            return self
        try:
            return self._stack[-1]
        except IndexError:
            return None

    def key(self):
        """get key of this resource

        Raises:
            NotImplementedError: key method not implemented
        """
        raise NotImplementedError('Class: {}'.format(self.__class__.__name__))

    def add_warning(self, warning):
        """Add warning on this resource

        Args:
            warning (str): warning to be added
        """
        self._warning.append(str(warning))

    def get_warning(self):
        """Get warning on this resource

        Returns:
            str: warning message
        """
        return '\n'.join(self._warning)

    # pylint: disable=broad-except
    def try_accept(self, visitor, stack=None):
        """Handle exceptions on the call the accept.

        Args:
            visitor (object): The class implementing the visitor pattern.
            stack (list): The resource stack from the root to immediate parent
                of this resource.
        """
        try:
            self.accept(visitor, stack)
        except Exception as e:
            LOGGER.exception(e)
            self.parent().add_warning(e)
            visitor.update(self.parent())
            visitor.on_child_error(e)

    def accept(self, visitor, stack=None):
        """Accept of resource in visitor pattern

        Args:
            visitor (Crawler): visitor instance
            stack (list): resource hierarchy stack
        """
        stack = [] if not stack else stack
        self._stack = stack
        self._visitor = visitor
        visitor.visit(self)
        for yielder_cls in self._contains:
            yielder = yielder_cls(self, visitor.get_client())
            try:
                for resource in yielder.iter():
                    res = resource
                    new_stack = stack + [self]

                    # Parallelization for resource subtrees.
                    if res.should_dispatch():
                        callback = partial(res.try_accept, visitor, new_stack)
                        visitor.dispatch(callback)
                    else:
                        res.try_accept(visitor, new_stack)
            except Exception as e:
                LOGGER.exception(e)
                self.add_warning(e)
                visitor.on_child_error(e)

        if self._warning:
            visitor.update(self)

    # pylint: enable=broad-except

    @cached('iam_policy')
    def get_iam_policy(self, client=None):
        """Get iam policy template

        Args:
            client (object): GCP API client
        """
        return None

    @cached('gcs_policy')
    def get_gcs_policy(self, client=None):
        """Get gcs policy template

        Args:
            client (object): GCP API client
        """
        return None

    @cached('sql_policy')
    def get_cloudsql_policy(self, client=None):
        """Get cloudsql policy template

        Args:
            client (object): GCP API client
        """
        return None

    @cached('dataset_policy')
    def get_dataset_policy(self, client=None):
        """Get dataset policy template

        Args:
            client (object): GCP API client
        """
        return None

    @cached('group_members')
    def get_group_members(self, client=None):
        """Get group member template

        Args:
            client (object): GCP API client
        """
        return None

    @cached('billing_info')
    def get_billing_info(self, client=None):
        """Get billing info template

        Args:
            client (object): GCP API client
        """
        return None

    @cached('enabled_apis')
    def get_enabled_apis(self, client=None):
        """Get enabled apis template

        Args:
            client (object): GCP API client
        """
        return None

    @cached('service_config')
    def get_kubernetes_service_config(self, client=None):
        """Get kubernetes service config mehod template

        Args:
            client (object): GCP API client
        """
        return None

    def get_timestamp(self):
        """template for timestamp when the resource object

        Returns:
            str: a string timestamp when the resource object was created.
        """
        return self._timestamp.strftime(string_formats.TIMESTAMP_UTC_OFFSET)

    def stack(self):
        """Get resource hierarchy stack of this resource

        Returns:
            list: resource hierarchy stack of this resource

        Raises:
            Exception: 'Stack not initialized yet'
        """
        if self._stack is None:
            raise Exception('Stack not initialized yet')
        return self._stack

    def visitor(self):
        """Get visitor on this resource

        Returns:
            Crawler: visitor on this resource

        Raises:
            Exception: 'Visitor not initialized yet'
        """
        if self._visitor is None:
            raise Exception('Visitor not initialized yet')
        return self._visitor

    def should_dispatch(self):
        """whether resources should run in parallel threads.

        Returns:
            bool: whether this resource should run in parallel threads.
        """
        return False

    def __repr__(self):
        """String Representation

        Returns:
            str: Resource representation
        """
        return ('{}<data="{}", parent_resource_type="{}", '
                'parent_resource_id="{}">').format(
                    self.__class__.__name__,
                    json.dumps(self._data),
                    self.parent().type(),
                    self.parent().key())


class Organization(Resource):
    """The Resource implementation for Organization
    """

    @classmethod
    def fetch(cls, client, resource_key):
        """Get Organization

        Saves ApiExecutionErrors as warnings.

        Args:
            client (object): GCP API client
            resource_key (str): resource key to fetch

        Returns:
            Organization: created Organization
        """
        try:
            data = client.fetch_organization(resource_key)
            return FACTORIES['organization'].create_new(data, root=True)
        except api_errors.ApiExecutionError as e:
            LOGGER.warn('Unable to fetch Organization %s: %s', resource_key, e)
            data = {'name': resource_key}
            resource = FACTORIES['organization'].create_new(data, root=True)
            resource.add_warning(e)
            return resource

    @cached('iam_policy')
    def get_iam_policy(self, client=None):
        """Get iam policy for this organization

        Args:
            client (object): GCP API client

        Returns:
            dict: organization IAM Policy
        """
        try:
            return client.get_organization_iam_policy(self['name'])
        except api_errors.ApiExecutionError as e:
            self.add_warning(e)
            return None

    def key(self):
        """Get key of this resource

        Returns:
            str: key of this resource
        """
        return self['name'].split('/', 1)[-1]

    @staticmethod
    def type():
        """Get type of this resource

        Returns:
            str: 'organization'
        """
        return 'organization'


class Folder(Resource):
    """The Resource implementation for Folder
    """

    @classmethod
    def fetch(cls, client, resource_key):
        """Get Folder

        Args:
            client (object): GCP API client
            resource_key (str): resource key to fetch

        Returns:
            Folder: created Folder
        """
        data = client.fetch_folder(resource_key)
        folder = FACTORIES['folder'].create_new(data, root=True)
        return folder

    def key(self):
        """Get key of this resource

        Returns:
            str: key of this resource
        """
        return self['name'].split('/', 1)[-1]

    @cached('iam_policy')
    def get_iam_policy(self, client=None):
        """Get iam policy for this folder

        Args:
            client (object): GCP API client

        Returns:
            dict: Folder IAM Policy
        """
        return client.get_folder_iam_policy(self['name'])

    @staticmethod
    def type():
        """Get type of this resource

        Returns:
            str: 'folder'
        """
        return 'folder'


class Project(Resource):
    """The Resource implementation for Project
    """

    @classmethod
    def fetch(cls, client, resource_key):
        """Get Project

        Args:
            client (object): GCP API client
            resource_key (str): resource key to fetch

        Returns:
            Project: created project
        """
        project_id = resource_key.split('/', 1)[-1]
        data = client.fetch_project(project_id)
        return FACTORIES['project'].create_new(data, root=True)

    @cached('iam_policy')
    def get_iam_policy(self, client=None):
        """Get iam policy for this project

        Args:
            client (object): GCP API client

        Returns:
            dict: Project IAM Policy
        """
        if self.enumerable():
            return client.get_project_iam_policy(self['projectId'])
        return {}

    @cached('billing_info')
    def get_billing_info(self, client=None):
        """Get billing info

        Args:
            client (object): GCP API client

        Returns:
            dict: Project Billing Info resource.
        """
        if self.enumerable():
            return client.get_project_billing_info(self['projectId'])
        return {}

    @cached('enabled_apis')
    def get_enabled_apis(self, client=None):
        """Get project enabled API services

        Args:
            client (object): GCP API client

        Returns:
            list: A list of ManagedService resource dicts.
        """
        enabled_apis = []
        if self.enumerable():
            enabled_apis = client.get_enabled_apis(self['projectId'])

        self._enabled_service_names = frozenset(
            (api.get('serviceName') for api in enabled_apis))
        return enabled_apis

    def key(self):
        """Get key of this resource

        Returns:
            str: key of this resource
        """
        return self['projectId']

    def should_dispatch(self):
        """Project resources should run in parallel threads.

        Returns:
            bool: whether project resources should run in parallel threads.
        """
        return True

    def enumerable(self):
        """whether this project is enumerable

        Returns:
            bool: if this project is enumerable
        """
        return self['lifecycleState'] == 'ACTIVE'

    def billing_enabled(self):
        """whether billing is enabled

        Returns:
            bool: if billing is enabled on the project.
        """
        return self.get_billing_info().get('billingEnabled', False)

    def is_api_enabled(self, service_name):
        """Returns True if the API service is enabled on the project.

        Args:
            service_name (str): The API service name to check.

        Returns:
            bool: whether a service api is enabled
        """
        return service_name in self._enabled_service_names

    def bigquery_api_enabled(self):
        """whether bigquery api is enabled

        Returns:
            bool: if this API service is enabled on the project.
        """
        # Bigquery API depends on billing being enabled
        return (self.billing_enabled() and
                self.is_api_enabled('bigquery-json.googleapis.com'))

    def cloudsql_api_enabled(self):
        """whether cloudsql api is enabled

        Returns:
            bool: if this API service is enabled on the project.
        """
        # CloudSQL Admin API depends on billing being enabled
        return (self.billing_enabled() and
                self.is_api_enabled('sql-component.googleapis.com'))

    def compute_api_enabled(self):
        """whether compute api is enabled

        Returns:
            bool: if this API service is enabled on the project.
        """
        # Compute API depends on billing being enabled
        return (self.billing_enabled() and
                self.is_api_enabled('compute.googleapis.com'))

    def container_api_enabled(self):
        """whether container api is enabled

        Returns:
            bool: if this API service is enabled on the project.
        """
        # Compute API depends on billing being enabled
        return (self.billing_enabled() and
                self.is_api_enabled('container.googleapis.com'))

    def storage_api_enabled(self):
        """whether storage api is enabled

        Returns:
            bool: if this API service is enabled on the project.
        """
        return self.is_api_enabled('storage-component.googleapis.com')

    @staticmethod
    def type():
        """Get type of this resource

        Returns:
            str: 'project'
        """
        return 'project'


class BillingAccount(Resource):
    """The Resource implementation for BillingAccount
    """

    def key(self):
        """Get key of this resource

        Returns:
            str: key of this resource
        """
        return self['name'].split('/', 1)[-1]

    @cached('iam_policy')
    def get_iam_policy(self, client=None):
        """Get iam policy for this folder

        Args:
            client (object): GCP API client

        Returns:
            dict: Billing Account IAM Policy
        """
        return client.get_billing_account_iam_policy(self['name'])

    @staticmethod
    def type():
        """Get type of this resource

        Returns:
            str: 'billing_account'
        """
        return 'billing_account'


class GcsBucket(Resource):
    """The Resource implementation for GcsBucket
    """

    @cached('iam_policy')
    def get_iam_policy(self, client=None):
        """Get IAM policy for this GCS bucket

        Args:
            client (object): GCP API client

        Returns:
            dict: bucket IAM policy
        """
        return client.get_bucket_iam_policy(self.key())

    def get_gcs_policy(self, client=None):
        """Full projection returns GCS policy with the resource.

        Args:
            client (object): GCP API client

        Returns:
            dict: bucket acl
        """
        # Full projection returns GCS policy with the resource.
        try:
            return self['acl']
        except KeyError:
            return []

    @staticmethod
    def type():
        """Get type of this resource

        Returns:
            str: 'bucket'
        """
        return 'bucket'

    def key(self):
        """Get key of this resource

        Returns:
            str: key of this resource
        """
        return self['id']


class GcsObject(Resource):
    """The Resource implementation for GcsObject
    """

    @cached('iam_policy')
    def get_iam_policy(self, client=None):
        """Get IAM policy for this GCS object

        Args:
            client (object): GCP API client

        Returns:
            dict: Object IAM policy
        """
        return client.get_object_iam_policy(self.parent()['name'],
                                            self['name'])

    def get_gcs_policy(self, client=None):
        """Full projection returns GCS policy with the resource.

        Args:
            client (object): GCP API client

        Returns:
            dict: Object acl
        """
        try:
            return self['acl']
        except KeyError:
            return []

    @staticmethod
    def type():
        """Get type of this resource

        Returns:
            str: 'storage_object'
        """
        return 'storage_object'

    def key(self):
        """Get key of this resource

        Returns:
            str: key of this resource
        """
        return self['id']


class KubernetesCluster(Resource):
    """The Resource implementation for KubernetesCluster
    """

    @cached('service_config')
    def get_kubernetes_service_config(self, client=None):
        """Get service config for KubernetesCluster

        Args:
            client (object): GCP API client

        Returns:
            dict: Generator of Kubernetes Engine Cluster resources.
        """
        try:
            return client.fetch_container_serviceconfig(
                self.parent().key(), zone=self.zone(), location=self.location())
        except ValueError:
            LOGGER.exception('Cluster has no zone or location: %s',
                             self._data)
            return {}

    def key(self):
        """Get key of this resource

        Returns:
            str: key of this resource
        """
        # Clusters do not have globally unique IDs, use size_t hash of selfLink
        return '%u' % ctypes.c_size_t(hash(self['selfLink'])).value

    @staticmethod
    def type():
        """Get type of this resource

        Returns:
            str: 'kubernetes_cluster'
        """
        return 'kubernetes_cluster'

    def location(self):
        """Get KubernetesCluster location

        Returns:
            str: KubernetesCluster location
        """
        try:
            self_link_parts = self['selfLink'].split('/')
            return self_link_parts[self_link_parts.index('locations') + 1]
        except (KeyError, ValueError):
            LOGGER.debug('selfLink not found or contains no locations: %s',
                         self._data)
            return None

    def zone(self):
        """Get KubernetesCluster zone

        Returns:
            str: KubernetesCluster zone
        """
        try:
            self_link_parts = self['selfLink'].split('/')
            return self_link_parts[self_link_parts.index('zones') + 1]
        except (KeyError, ValueError):
            LOGGER.debug('selfLink not found or contains no zones: %s',
                         self._data)
            return None


class DataSet(Resource):
    """The Resource implementation for DataSet"""

    @cached('dataset_policy')
    def get_dataset_policy(self, client=None):
        """Dataset policy for this Dataset

        Args:
            client (object): GCP API client

        Returns:
            dict: Dataset Policy
        """
        return client.get_dataset_dataset_policy(
            self.parent().key(),
            self['datasetReference']['datasetId'])

    def key(self):
        """Get key of this resource

        Returns:
            str: key of this resource
        """
        return self['id']

    @staticmethod
    def type():
        """Get type of this resource

        Returns:
            str: 'dataset'
        """
        return 'dataset'


class AppEngineApp(Resource):
    """The Resource implementation for AppEngineApp"""

    def key(self):
        """Get key of this resource

        Returns:
            str: key of this resource
        """
        # Apps do not have globally unique IDs, use size_t hash of name
        return '%u' % ctypes.c_size_t(hash(self['name'])).value

    @staticmethod
    def type():
        """Get type of this resource

        Returns:
            str: 'appengine_app'
        """
        return 'appengine_app'


class AppEngineService(Resource):
    """The Resource implementation for AppEngineService"""

    def key(self):
        """Get key of this resource

        Returns:
            str: key of this resource
        """
        # Services do not have globally unique IDs, use size_t hash of name
        return '%u' % ctypes.c_size_t(hash(self['name'])).value

    @staticmethod
    def type():
        """Get type of this resource

        Returns:
            str: 'appengine_service'
        """
        return 'appengine_service'


class AppEngineVersion(Resource):
    """The Resource implementation for AppEngineVersion"""

    def key(self):
        """Get key of this resource

        Returns:
            str: key of this resource
        """
        # Versions do not have globally unique IDs, use size_t hash of name
        return '%u' % ctypes.c_size_t(hash(self['name'])).value

    @staticmethod
    def type():
        """Get type of this resource

        Returns:
            str: 'appengine_version'
        """
        return 'appengine_version'


class AppEngineInstance(Resource):
    """The Resource implementation for AppEngineInstance"""

    def key(self):
        """Get key of this resource

        Returns:
            str: key of this resource
        """
        # Instances do not have globally unique IDs, use size_t hash of name
        return '%u' % ctypes.c_size_t(hash(self['name'])).value

    @staticmethod
    def type():
        """Get type of this resource

        Returns:
            str: 'appengine_instance'
        """
        return 'appengine_instance'


class ComputeProject(Resource):
    """The Resource implementation for ComputeProject"""

    def key(self):
        """Get key of this resource

        Returns:
            str: key of this resource
        """
        return self['id']

    @staticmethod
    def type():
        """Get type of this resource

        Returns:
            str: 'compute_project'
        """
        return 'compute_project'


class Disk(Resource):
    """The Resource implementation for Disk"""

    def key(self):
        """Get key of this resource

        Returns:
            str: key of this resource
        """
        return self['id']

    @staticmethod
    def type():
        """Get type of this resource

        Returns:
            str: 'disk'
        """
        return 'disk'


class Instance(Resource):
    """The Resource implementation for Instance"""

    def key(self):
        """Get key of this resource

        Returns:
            str: key of this resource
        """
        return self['id']

    @staticmethod
    def type():
        """Get type of this resource

        Returns:
            str: 'instance'
        """
        return 'instance'


class Firewall(Resource):
    """The Resource implementation for Firewall"""

    def key(self):
        """Get key of this resource

        Returns:
            str: key of this resource
        """
        return self['id']

    @staticmethod
    def type():
        """Get type of this resource

        Returns:
            str: 'firewall'
        """
        return 'firewall'


class Image(Resource):
    """The Resource implementation for Image"""

    def key(self):
        """Get key of this resource

        Returns:
            str: key of this resource
        """
        return self['id']

    @staticmethod
    def type():
        """Get type of this resource

        Returns:
            str: 'image'
        """
        return 'image'


class InstanceGroup(Resource):
    """The Resource implementation for InstanceGroup"""

    def key(self):
        """Get key of this resource

        Returns:
            str: key of this resource
        """
        return self['id']

    @staticmethod
    def type():
        """Get type of this resource

        Returns:
            str: 'instancegroup'
        """
        return 'instancegroup'


class InstanceGroupManager(Resource):
    """The Resource implementation for InstanceGroupManager"""

    def key(self):
        """Get key of this resource

        Returns:
            str: key of this resource
        """
        return self['id']

    @staticmethod
    def type():
        """Get type of this resource

        Returns:
            str: 'instancegroupmanager'
        """
        return 'instancegroupmanager'


class InstanceTemplate(Resource):
    """The Resource implementation for InstanceTemplate"""

    def key(self):
        """Get key of this resource

        Returns:
            str: key of this resource
        """
        return self['id']

    @staticmethod
    def type():
        """Get type of this resource

        Returns:
            str: 'instancetemplate'
        """
        return 'instancetemplate'


class Network(Resource):
    """The Resource implementation for Network"""

    def key(self):
        """Get key of this resource

        Returns:
            str: key of this resource
        """
        return self['id']

    @staticmethod
    def type():
        """Get type of this resource

        Returns:
            str: 'network'
        """
        return 'network'


class Snapshot(Resource):
    """The Resource implementation for Snapshot"""

    def key(self):
        """Get key of this resource

        Returns:
            str: key of this resource
        """
        return self['id']

    @staticmethod
    def type():
        """Get type of this resource

        Returns:
            str: 'snapshot'
        """
        return 'snapshot'


class Subnetwork(Resource):
    """The Resource implementation for Subnetwork"""

    def key(self):
        """Get key of this resource

        Returns:
            str: key of this resource
        """
        return self['id']

    @staticmethod
    def type():
        """Get type of this resource

        Returns:
            str: 'subnetwork'
        """
        return 'subnetwork'


class BackendService(Resource):
    """The Resource implementation for BackendService"""

    def key(self):
        """Get key of this resource

        Returns:
            str: key of this resource
        """
        return self['id']

    @staticmethod
    def type():
        """Get type of this resource

        Returns:
            str: 'backendservice'
        """
        return 'backendservice'


class ForwardingRule(Resource):
    """The Resource implementation for ForwardingRule"""

    def key(self):
        """Get key of this resource

        Returns:
            str: key of this resource
        """
        return self['id']

    @staticmethod
    def type():
        """Get type of this resource

        Returns:
            str: 'forwardingrule'
        """
        return 'forwardingrule'


class CuratedRole(Resource):
    """The Resource implementation for CuratedRole"""

    def key(self):
        """Get key of this resource

        Returns:
            str: key of this resource
        """
        return self['name']

    @staticmethod
    def type():
        """Get type of this resource

        Returns:
            str: 'role'
        """
        return 'role'

    def parent(self):
        """Get parent of this resource

        curated role doesn't have parent
        """
        # Curated roles have no parent.
        return None


class Role(Resource):
    """The Resource implementation for role"""

    def key(self):
        """Get key of this resource

        Returns:
            str: key of this resource
        """
        return self['name']

    @staticmethod
    def type():
        """Get type of this resource

        Returns:
            str: 'role'
        """
        return 'role'


class CloudSqlInstance(Resource):
    """The Resource implementation for cloudsqlinstance"""

    def key(self):
        """Get key of this resource

        Returns:
            str: id key of this resource
        """
        return self['name']

    @staticmethod
    def type():
        """Get type of this resource

        Returns:
            str: 'cloudsqlinstance'
        """
        return 'cloudsqlinstance'


class ServiceAccount(Resource):
    """The Resource implementation for serviceaccount"""

    @cached('iam_policy')
    def get_iam_policy(self, client=None):
        """Service Account IAM policy for this service account

        Args:
            client (object): GCP API client

        Returns:
            dict: Service Account IAM policy.
        """
        return client.get_serviceaccount_iam_policy(self['name'])

    def key(self):
        """Get key of this resource

        Returns:
            str: id key of this resource
        """
        return self['uniqueId']

    @staticmethod
    def type():
        """Get type of this resource

        Returns:
            str: 'serviceaccount'
        """
        return 'serviceaccount'


class Sink(Resource):
    """The Resource implementation for Stackdriver Logging sink"""

    def key(self):
        """Get key of this resource

        Returns:
            str: key of this resource
        """
        sink_name = '/'.join([self.parent().type(), self.parent().key(),
                              self.type(), self['name']])
        return sink_name

    @staticmethod
    def type():
        """Get type of this resource

        Returns:
            str: 'sink'
        """
        return 'sink'


class ServiceAccountKey(Resource):
    """The Resource implementation for serviceaccount_key"""

    def key(self):
        """Get key of this resource

        Key name is in the format:
           projects/{project_id}/serviceAccounts/{service_account}/keys/{key_id}
        Returns:
            str: id key of this resource
        """
        return self['name'].split('/')[-1]

    @staticmethod
    def type():
        """Get type of this resource

        Returns:
            str: 'serviceaccount_key'
        """
        return 'serviceaccount_key'


class GsuiteUser(Resource):
    """The Resource implementation for gsuite_user"""

    def key(self):
        """Get key of this resource

        Returns:
            str: id key of this resource
        """
        return self['id']

    @staticmethod
    def type():
        """Get type of this resource

        Returns:
            str: 'gsuite_user'
        """
        return 'gsuite_user'


class GsuiteGroup(Resource):
    """The Resource implementation for gsuite_group"""

    def key(self):
        """Get key of this resource

        Returns:
            str: id key of this resource
        """
        return self['id']

    @staticmethod
    def type():
        """Get type of this resource

        Returns:
            str: 'gsuite_group'
        """
        return 'gsuite_group'


class GsuiteUserMember(Resource):
    """The Resource implementation for gsuite_user_member"""

    def key(self):
        """Get key of this resource

        Returns:
            str: id key of this resource
        """
        return self['id']

    @staticmethod
    def type():
        """Get type of this resource

        Returns:
            str: 'gsuite_user_member'
        """
        return 'gsuite_user_member'


class GsuiteGroupMember(Resource):
    """The Resource implementation for gsuite_group_member"""

    def key(self):
        """Get key of this resource

        Returns:
            str: id key of this resource
        """
        return self['id']

    @staticmethod
    def type():
        """Get type of this resource

        Returns:
            str: 'gsuite_group_member'
        """
        return 'gsuite_group_member'


class ResourceIterator(object):
    """The Resource iterator template"""

    def __init__(self, resource, client):
        """Initialize

        Args:
            resource (Resource): The parent
            client (object): GCP API Client
        """
        self.resource = resource
        self.client = client

    def iter(self):
        """Raises:
            NotImplementedError: Abstract class method not implemented
        """
        raise NotImplementedError()


class FolderIterator(ResourceIterator):
    """The Resource iterator implementation for Folder"""

    def iter(self):
        """Yields:
            Resource: Folder created
        """
        gcp = self.client
        for data in gcp.iter_folders(parent_id=self.resource['name']):
            yield FACTORIES['folder'].create_new(data)


class FolderFolderIterator(ResourceIterator):
    """The Resource iterator implementation for Folder"""

    def iter(self):
        """Yields:
            Resource: Folder created
        """
        gcp = self.client
        for data in gcp.iter_folders(parent_id=self.resource['name']):
            yield FACTORIES['folder'].create_new(data)


class ProjectIterator(ResourceIterator):
    """The Resource iterator implementation for Project"""

    def iter(self):
        """Yields:
            Resource: Project created
        """
        gcp = self.client
        orgid = self.resource['name'].split('/', 1)[-1]
        for data in gcp.iter_projects(parent_type='organization',
                                      parent_id=orgid):
            yield FACTORIES['project'].create_new(data)


class FolderProjectIterator(ResourceIterator):
    """The Resource iterator implementation for Project"""

    def iter(self):
        """Yields:
            Resource: Project created
        """
        gcp = self.client
        folderid = self.resource['name'].split('/', 1)[-1]
        for data in gcp.iter_projects(parent_type='folder',
                                      parent_id=folderid):
            yield FACTORIES['project'].create_new(data)


class BillingAccountIterator(ResourceIterator):
    """The Resource iterator implementation for BillingAccount"""

    def iter(self):
        """Yields:
            Resource: BillingAccount created
        """
        gcp = self.client
        for data in gcp.iter_billing_accounts():
            yield FACTORIES['billing_account'].create_new(data)


class BucketIterator(ResourceIterator):
    """The Resource iterator implementation for GcsBucket"""

    def iter(self):
        """Yields:
            Resource: GcsBucket created
        """
        gcp = self.client
        if self.resource.storage_api_enabled():
            for data in gcp.iter_buckets(
                    projectid=self.resource['projectNumber']):
                yield FACTORIES['bucket'].create_new(data)


class ObjectIterator(ResourceIterator):
    """The Resource iterator implementation for GcsObject"""

    def iter(self):
        """Yields:
            Resource: GcsObject created
        """
        gcp = self.client
        for data in gcp.iter_objects(bucket_id=self.resource['id']):
            yield FACTORIES['object'].create_new(data)


class DataSetIterator(ResourceIterator):
    """The Resource iterator implementation for Dataset"""

    def iter(self):
        """Yields:
            Resource: Dataset created
        """
        gcp = self.client
        if self.resource.bigquery_api_enabled():
            for data in gcp.iter_datasets(
                    projectid=self.resource['projectNumber']):
                yield FACTORIES['dataset'].create_new(data)


class AppEngineAppIterator(ResourceIterator):
    """The Resource iterator implementation for AppEngineApp"""

    def iter(self):
        """Yields:
            Resource: AppEngineApp created
        """
        gcp = self.client
        if self.resource.enumerable():
            data = gcp.fetch_gae_app(projectid=self.resource['projectId'])
            if data:
                yield FACTORIES['appengine_app'].create_new(data)


class AppEngineServiceIterator(ResourceIterator):
    """The Resource iterator implementation for AppEngineService"""

    def iter(self):
        """Yields:
            Resource: AppEngineService created
        """
        gcp = self.client
        for data in gcp.iter_gae_services(projectid=self.resource['id']):
            yield FACTORIES['appengine_service'].create_new(data)


class AppEngineVersionIterator(ResourceIterator):
    """The Resource iterator implementation for AppEngineVersion"""

    def iter(self):
        """Yields:
            Resource: AppEngineVersion created
        """
        gcp = self.client
        for data in gcp.iter_gae_versions(
                projectid=self.resource.parent()['id'],
                serviceid=self.resource['id']):
            yield FACTORIES['appengine_version'].create_new(data)


class AppEngineInstanceIterator(ResourceIterator):
    """The Resource iterator implementation for AppEngineInstance"""

    def iter(self):
        """Yields:
            Resource: AppEngineInstance created
        """
        gcp = self.client
        for data in gcp.iter_gae_instances(
                projectid=self.resource.parent().parent()['id'],
                serviceid=self.resource.parent()['id'],
                versionid=self.resource['id']):
            yield FACTORIES['appengine_instance'].create_new(data)


class KubernetesClusterIterator(ResourceIterator):
    """The Resource iterator implementation for KubernetesCluster"""

    def iter(self):
        """Yields:
            Resource: KubernetesCluster created
        """
        gcp = self.client
        if self.resource.container_api_enabled():
            for data in gcp.iter_container_clusters(
                    projectid=self.resource['projectId']):
                yield FACTORIES['kubernetes_cluster'].create_new(data)


class ComputeIterator(ResourceIterator):
    """The Resource iterator implementation for ComputeProject"""

    def iter(self):
        """Yields:
            Resource: ComputeProject created
        """
        gcp = self.client
        if self.resource.compute_api_enabled():
            data = gcp.fetch_compute_project(
                projectid=self.resource['projectId'])
            yield FACTORIES['compute'].create_new(data)


class DiskIterator(ResourceIterator):
    """The Resource iterator implementation for Disk"""

    def iter(self):
        """Yields:
            Resource: Disk created
        """
        gcp = self.client
        if self.resource.compute_api_enabled():
            for data in gcp.iter_computedisks(
                    projectid=self.resource['projectId']):
                yield FACTORIES['disk'].create_new(data)


class InstanceIterator(ResourceIterator):
    """The Resource iterator implementation for Instance"""

    def iter(self):
        """Yields:
            Resource: Instance created
        """
        gcp = self.client
        if self.resource.compute_api_enabled():
            for data in gcp.iter_computeinstances(
                    projectid=self.resource['projectId']):
                yield FACTORIES['instance'].create_new(data)


class FirewallIterator(ResourceIterator):
    """The Resource iterator implementation for Firewall"""

    def iter(self):
        """Yields:
            Resource: Firewall created
        """
        gcp = self.client
        if self.resource.compute_api_enabled():
            for data in gcp.iter_computefirewalls(
                    projectid=self.resource['projectId']):
                yield FACTORIES['firewall'].create_new(data)


class ImageIterator(ResourceIterator):
    """The Resource iterator implementation for Image"""

    def iter(self):
        """Yields:
            Resource: Image created
        """
        gcp = self.client
        if self.resource.compute_api_enabled():
            for data in gcp.iter_images(
                    projectid=self.resource['projectId']):
                yield FACTORIES['image'].create_new(data)


class InstanceGroupIterator(ResourceIterator):
    """The Resource iterator implementation for InstanceGroup"""

    def iter(self):
        """Yields:
            Resource: InstanceGroup created
        """
        gcp = self.client
        if self.resource.compute_api_enabled():
            for data in gcp.iter_computeinstancegroups(
                    projectid=self.resource['projectId']):
                yield FACTORIES['instancegroup'].create_new(data)


class InstanceGroupManagerIterator(ResourceIterator):
    """The Resource iterator implementation for InstanceGroupManager"""

    def iter(self):
        """Yields:
            Resource: InstanceGroupManager created
        """
        gcp = self.client
        if self.resource.compute_api_enabled():
            for data in gcp.iter_ig_managers(
                    projectid=self.resource['projectId']):
                yield FACTORIES['instancegroupmanager'].create_new(data)


class InstanceTemplateIterator(ResourceIterator):
    """The Resource iterator implementation for InstanceTemplate"""

    def iter(self):
        """Yields:
            Resource: InstanceTemplate created
        """
        gcp = self.client
        if self.resource.compute_api_enabled():
            for data in gcp.iter_instancetemplates(
                    projectid=self.resource['projectId']):
                yield FACTORIES['instancetemplate'].create_new(data)


class NetworkIterator(ResourceIterator):
    """The Resource iterator implementation for Network"""

    def iter(self):
        """Yields:
            Resource: Network created
        """
        gcp = self.client
        if self.resource.compute_api_enabled():
            for data in gcp.iter_networks(
                    projectid=self.resource['projectId']):
                yield FACTORIES['network'].create_new(data)


class SnapshotIterator(ResourceIterator):
    """The Resource iterator implementation for Snapshot"""

    def iter(self):
        """Yields:
            Resource: Snapshot created
        """
        gcp = self.client
        if self.resource.compute_api_enabled():
            for data in gcp.iter_snapshots(
                    projectid=self.resource['projectId']):
                yield FACTORIES['snapshot'].create_new(data)


class SubnetworkIterator(ResourceIterator):
    """The Resource iterator implementation for Subnetwork"""

    def iter(self):
        """Yields:
            Resource: Subnetwork created
        """
        gcp = self.client
        if self.resource.compute_api_enabled():
            for data in gcp.iter_subnetworks(
                    projectid=self.resource['projectId']):
                yield FACTORIES['subnetwork'].create_new(data)


class BackendServiceIterator(ResourceIterator):
    """The Resource iterator implementation for BackendService"""

    def iter(self):
        """Yields:
            Resource: BackendService created
        """
        gcp = self.client
        if self.resource.compute_api_enabled():
            for data in gcp.iter_backendservices(
                    projectid=self.resource['projectId']):
                yield FACTORIES['backendservice'].create_new(data)


class ForwardingRuleIterator(ResourceIterator):
    """The Resource iterator implementation for ForwardingRule"""

    def iter(self):
        """Yields:
            Resource: ForwardingRule created
        """
        gcp = self.client
        if self.resource.compute_api_enabled():
            for data in gcp.iter_forwardingrules(
                    projectid=self.resource['projectId']):
                yield FACTORIES['forwardingrule'].create_new(data)


class CloudSqlIterator(ResourceIterator):
    """The Resource iterator implementation for CloudSqlInstance"""

    def iter(self):
        """Yields:
            Resource: CloudSqlInstance created
        """
        gcp = self.client
        if self.resource.cloudsql_api_enabled():
            for data in gcp.iter_cloudsqlinstances(
                    projectid=self.resource['projectId']):
                yield FACTORIES['cloudsqlinstance'].create_new(data)


class ServiceAccountIterator(ResourceIterator):
    """The Resource iterator implementation for ServiceAccount"""

    def iter(self):
        """Yields:
            Resource: ServiceAccount created
        """
        gcp = self.client
        if self.resource.enumerable():
            for data in gcp.iter_serviceaccounts(
                    projectid=self.resource['projectId']):
                yield FACTORIES['serviceaccount'].create_new(data)


class ServiceAccountKeyIterator(ResourceIterator):
    """The Resource iterator implementation for ServiceAccountKey"""

    def iter(self):
        """Yields:
            Resource: ServiceAccountKey created
        """
        gcp = self.client
        for data in gcp.iter_serviceaccount_exported_keys(
                name=self.resource['name']):
            yield FACTORIES['serviceaccount_key'].create_new(data)


class ProjectRoleIterator(ResourceIterator):
    """The Resource iterator implementation for Project Role"""

    def iter(self):
        """Yields:
            Resource: Role created
        """
        gcp = self.client
        if self.resource.enumerable():
            for data in gcp.iter_project_roles(
                    projectid=self.resource['projectId']):
                yield FACTORIES['role'].create_new(data)


class OrganizationRoleIterator(ResourceIterator):
    """The Resource iterator implementation for Organization Role"""

    def iter(self):
        """Yields:
            Resource: Role created
        """
        gcp = self.client
        for data in gcp.iter_organization_roles(
                orgid=self.resource['name']):
            yield FACTORIES['role'].create_new(data)


class OrganizationCuratedRoleIterator(ResourceIterator):
    """The Resource iterator implementation for OrganizationCuratedRole"""

    def iter(self):
        """Yields:
            Resource: CuratedRole created
        """
        gcp = self.client
        for data in gcp.iter_curated_roles():
            yield FACTORIES['curated_role'].create_new(data)


class GsuiteGroupIterator(ResourceIterator):
    """The Resource iterator implementation for GsuiteGroup"""

    def iter(self):
        """Yields:
            Resource: GsuiteGroup created
        """
        gsuite = self.client
        for data in gsuite.iter_groups(
                self.resource['owner']['directoryCustomerId']):
            yield FACTORIES['gsuite_group'].create_new(data)


class GsuiteUserIterator(ResourceIterator):
    """The Resource iterator implementation for GsuiteUser"""

    def iter(self):
        """Yields:
            Resource: GsuiteUser created
        """
        gsuite = self.client
        for data in gsuite.iter_users(
                self.resource['owner']['directoryCustomerId']):
            yield FACTORIES['gsuite_user'].create_new(data)


class GsuiteMemberIterator(ResourceIterator):
    """The Resource iterator implementation for GsuiteMember"""

    def iter(self):
        """Yields:
            Resource: GsuiteUserMember or GsuiteGroupMember created
        """
        gsuite = self.client
        for data in gsuite.iter_group_members(self.resource['id']):
            if data['type'] == 'USER':
                yield FACTORIES['gsuite_user_member'].create_new(data)
            elif data['type'] == 'GROUP':
                yield FACTORIES['gsuite_group_member'].create_new(data)


class ProjectSinkIterator(ResourceIterator):
    """The Resource iterator implementation for Project Sink"""

    def iter(self):
        """Yields:
            Resource: Sink created
        """
        gcp = self.client
        if self.resource.enumerable():
            for data in gcp.iter_project_sinks(
                    projectid=self.resource['projectId']):
                yield FACTORIES['sink'].create_new(data)


class FolderSinkIterator(ResourceIterator):
    """The Resource iterator implementation for Folder Sink"""

    def iter(self):
        """Yields:
            Resource: Sink created
        """
        gcp = self.client
        for data in gcp.iter_folder_sinks(folderid=self.resource['name']):
            yield FACTORIES['sink'].create_new(data)


class OrganizationSinkIterator(ResourceIterator):
    """The Resource iterator implementation for Organization Sink"""

    def iter(self):
        """Yields:
            Resource: Sink created
        """
        gcp = self.client
        for data in gcp.iter_organization_sinks(orgid=self.resource['name']):
            yield FACTORIES['sink'].create_new(data)


class BillingAccountSinkIterator(ResourceIterator):
    """The Resource iterator implementation for Billing Account Sink"""

    def iter(self):
        """Yields:
            Resource: Sink created
        """
        gcp = self.client
        for data in gcp.iter_billing_account_sinks(
                acctid=self.resource['name']):
            yield FACTORIES['sink'].create_new(data)


FACTORIES = {
    'organization': ResourceFactory({
        'dependsOn': [],
        'cls': Organization,
        'contains': [
            GsuiteGroupIterator,
            GsuiteUserIterator,
            FolderIterator,
            OrganizationRoleIterator,
            OrganizationCuratedRoleIterator,
            OrganizationSinkIterator,
            BillingAccountIterator,
            ProjectIterator,
        ]}),

    'folder': ResourceFactory({
        'dependsOn': ['organization'],
        'cls': Folder,
        'contains': [
            FolderFolderIterator,
            FolderProjectIterator,
            FolderSinkIterator,
        ]}),

    'project': ResourceFactory({
        'dependsOn': ['organization', 'folder'],
        'cls': Project,
        'contains': [
            BucketIterator,
            DataSetIterator,
            CloudSqlIterator,
            ServiceAccountIterator,
            AppEngineAppIterator,
            KubernetesClusterIterator,
            ComputeIterator,
            DiskIterator,
            ImageIterator,
            InstanceIterator,
            FirewallIterator,
            InstanceGroupIterator,
            InstanceGroupManagerIterator,
            InstanceTemplateIterator,
            BackendServiceIterator,
            ForwardingRuleIterator,
            NetworkIterator,
            SnapshotIterator,
            SubnetworkIterator,
            ProjectRoleIterator,
            ProjectSinkIterator
        ]}),

    'billing_account': ResourceFactory({
        'dependsOn': ['organization'],
        'cls': BillingAccount,
        'contains': [
            BillingAccountSinkIterator,
        ]}),

    'appengine_app': ResourceFactory({
        'dependsOn': ['project'],
        'cls': AppEngineApp,
        'contains': [
            AppEngineServiceIterator,
        ]}),

    'appengine_service': ResourceFactory({
        'dependsOn': ['appengine_app'],
        'cls': AppEngineService,
        'contains': [
            AppEngineVersionIterator,
        ]}),

    'appengine_version': ResourceFactory({
        'dependsOn': ['appengine_service'],
        'cls': AppEngineVersion,
        'contains': [
            AppEngineInstanceIterator,
        ]}),

    'appengine_instance': ResourceFactory({
        'dependsOn': ['appengine_version'],
        'cls': AppEngineInstance,
        'contains': [
        ]}),

    'bucket': ResourceFactory({
        'dependsOn': ['project'],
        'cls': GcsBucket,
        'contains': [
            # ObjectIterator
        ]}),

    'object': ResourceFactory({
        'dependsOn': ['bucket'],
        'cls': GcsObject,
        'contains': [
        ]}),

    'dataset': ResourceFactory({
        'dependsOn': ['project'],
        'cls': DataSet,
        'contains': [
        ]}),

    'kubernetes_cluster': ResourceFactory({
        'dependsOn': ['project'],
        'cls': KubernetesCluster,
        'contains': [
        ]}),

    'compute': ResourceFactory({
        'dependsOn': ['project'],
        'cls': ComputeProject,
        'contains': [
        ]}),

    'disk': ResourceFactory({
        'dependsOn': ['project'],
        'cls': Disk,
        'contains': [
        ]}),

    'instance': ResourceFactory({
        'dependsOn': ['project'],
        'cls': Instance,
        'contains': [
        ]}),

    'firewall': ResourceFactory({
        'dependsOn': ['project'],
        'cls': Firewall,
        'contains': [
        ]}),

    'image': ResourceFactory({
        'dependsOn': ['project'],
        'cls': Image,
        'contains': [
        ]}),

    'instancegroup': ResourceFactory({
        'dependsOn': ['project'],
        'cls': InstanceGroup,
        'contains': [
        ]}),

    'instancegroupmanager': ResourceFactory({
        'dependsOn': ['project'],
        'cls': InstanceGroupManager,
        'contains': [
        ]}),

    'instancetemplate': ResourceFactory({
        'dependsOn': ['project'],
        'cls': InstanceTemplate,
        'contains': [
        ]}),

    'backendservice': ResourceFactory({
        'dependsOn': ['project'],
        'cls': BackendService,
        'contains': [
        ]}),

    'forwardingrule': ResourceFactory({
        'dependsOn': ['project'],
        'cls': ForwardingRule,
        'contains': [
        ]}),

    'network': ResourceFactory({
        'dependsOn': ['project'],
        'cls': Network,
        'contains': [
        ]}),

    'snapshot': ResourceFactory({
        'dependsOn': ['project'],
        'cls': Snapshot,
        'contains': [
        ]}),

    'subnetwork': ResourceFactory({
        'dependsOn': ['project'],
        'cls': Subnetwork,
        'contains': [
        ]}),

    'cloudsqlinstance': ResourceFactory({
        'dependsOn': ['project'],
        'cls': CloudSqlInstance,
        'contains': [
        ]}),

    'serviceaccount': ResourceFactory({
        'dependsOn': ['project'],
        'cls': ServiceAccount,
        'contains': [
            ServiceAccountKeyIterator
        ]}),

    'serviceaccount_key': ResourceFactory({
        'dependsOn': ['serviceaccount'],
        'cls': ServiceAccountKey,
        'contains': [
        ]}),

    'role': ResourceFactory({
        'dependsOn': ['organization', 'project'],
        'cls': Role,
        'contains': [
        ]}),

    'curated_role': ResourceFactory({
        'dependsOn': [],
        'cls': CuratedRole,
        'contains': [
        ]}),

    'gsuite_user': ResourceFactory({
        'dependsOn': ['organization'],
        'cls': GsuiteUser,
        'contains': [
        ]}),

    'gsuite_group': ResourceFactory({
        'dependsOn': ['organization'],
        'cls': GsuiteGroup,
        'contains': [
            GsuiteMemberIterator,
        ]}),

    'gsuite_user_member': ResourceFactory({
        'dependsOn': ['gsuite_group'],
        'cls': GsuiteUserMember,
        'contains': [
        ]}),

    'gsuite_group_member': ResourceFactory({
        'dependsOn': ['gsuite_group'],
        'cls': GsuiteGroupMember,
        'contains': [
        ]}),

    'sink': ResourceFactory({
        'dependsOn': ['organization', 'folder', 'project'],
        'cls': Sink,
        'contains': [
        ]}),
}
