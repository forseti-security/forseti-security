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

# TODO: The next editor must remove this disable and correct issues.
# pylint: disable=missing-return-type-doc,missing-return-doc,broad-except
# pylint: disable=missing-docstring,unused-argument,invalid-name
# pylint: disable=no-self-use,missing-yield-doc,missing-yield-type-doc,attribute-defined-outside-init
# pylint: disable=useless-suppression,cell-var-from-loop,protected-access,too-many-instance-attributes

import ctypes
from concurrent.futures import as_completed
import json


def from_root_id(client, root_id):
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
    field_name = '__cached_{}'.format(field_name)

    def _cached(f):
        def wrapper(*args, **kwargs):
            if hasattr(args[0], field_name):
                return getattr(args[0], field_name)
            result = f(*args, **kwargs)
            setattr(args[0], field_name, result)
            return result
        return wrapper
    return _cached


class ResourceFactory(object):
    def __init__(self, attributes):
        self.attributes = attributes

    def create_new(self, data, root=False):
        attrs = self.attributes
        cls = attrs['cls']
        return cls(data, root, **attrs)


class ResourceKey(object):
    def __init__(self, res_type, res_id):
        self.res_type = res_type
        self.res_id = res_id


class Resource(object):
    def __init__(self, data, root=False, contains=None, **kwargs):
        self._data = data
        self._root = root
        self._stack = None
        self._contains = [] if contains is None else contains
        self._warning = []
        self._enabled_service_names = None

    def __getitem__(self, key):
        try:
            return self._data[key]
        except KeyError:
            raise KeyError('key: {}, data: {}'.format(key, self._data))

    def __setitem__(self, key, value):
        self._data[key] = value

    def type(self):
        raise NotImplementedError('Class: {}'.format(self.__class__.__name__))

    def data(self):
        return self._data

    def parent(self):
        if self._root:
            return self
        try:
            return self._stack[-1]
        except IndexError:
            return None

    def key(self):
        raise NotImplementedError('Class: {}'.format(self.__class__.__name__))

    def add_warning(self, warning):
        self._warning.append(str(warning))

    def get_warning(self):
        return '\n'.join(self._warning)

    def accept(self, visitor, stack=None):
        stack = [] if not stack else stack
        self._stack = stack
        self._visitor = visitor
        dispatched_resources = []
        visitor.visit(self)
        for yielder_cls in self._contains:
            yielder = yielder_cls(self, visitor.get_client())
            try:
                for resource in yielder.iter():
                    res = resource
                    new_stack = stack + [self]

                    if res.type() != 'project':
                        res.accept(visitor, new_stack)

                    # Parallelization for project resources.
                    else:
                        future = visitor.dispatch(
                            res.accept, visitor, new_stack)
                        dispatched_resources.append(future)
            except Exception as e:
                self.add_warning(e)
                visitor.on_child_error(e)

        for future in as_completed(dispatched_resources):
            if future.exception():
                self.add_warning(future.exception())
                visitor.on_child_error(future.exception())
        if self._warning:
            visitor.update(self)

    @cached('iam_policy')
    def getIamPolicy(self, client=None):
        return None

    @cached('gcs_policy')
    def getGCSPolicy(self, client=None):
        return None

    @cached('sql_policy')
    def getCloudSQLPolicy(self, client=None):
        return None

    @cached('dataset_policy')
    def getDatasetPolicy(self, client=None):
        return None

    @cached('group_members')
    def getGroupMembers(self, client=None):
        return None

    @cached('billing_info')
    def getBillingInfo(self, client=None):
        return None

    @cached('enabled_apis')
    def getEnabledAPIs(self, client=None):
        return None

    def stack(self):
        if self._stack is None:
            raise Exception('Stack not initialized yet')
        return self._stack

    def visitor(self):
        if self._visitor is None:
            raise Exception('Visitor not initialized yet')
        return self._visitor

    def __repr__(self):
        return '{}<data="{}", parent_type="{}", parent_key="{}">'.format(
            self.__class__.__name__,
            json.dumps(self._data),
            self.parent().type(),
            self.parent().key())


class Organization(Resource):
    @classmethod
    def fetch(cls, client, resource_key):
        data = client.fetch_organization(resource_key)
        return FACTORIES['organization'].create_new(data, root=True)

    @cached('iam_policy')
    def getIamPolicy(self, client=None):
        return client.get_organization_iam_policy(self['name'])

    def key(self):
        return self['name'].split('/', 1)[-1]

    def type(self):
        return 'organization'


class Folder(Resource):
    @classmethod
    def fetch(cls, client, resource_key):
        data = client.fetch_folder(resource_key)
        folder = FACTORIES['folder'].create_new(data, root=True)
        return folder

    def key(self):
        return self['name'].split('/', 1)[-1]

    @cached('iam_policy')
    def getIamPolicy(self, client=None):
        return client.get_folder_iam_policy(self['name'])

    def type(self):
        return 'folder'


class Project(Resource):
    @classmethod
    def fetch(cls, client, resource_key):
        project_id = resource_key.split('/', 1)[-1]
        data = client.fetch_project(project_id)
        return FACTORIES['project'].create_new(data, root=True)

    @cached('iam_policy')
    def getIamPolicy(self, client=None):
        if self.enumerable():
            return client.get_project_iam_policy(self['projectId'])
        return {}

    @cached('billing_info')
    def getBillingInfo(self, client=None):
        if self.enumerable():
            return client.get_project_billing_info(self['projectId'])
        return {}

    @cached('enabled_apis')
    def getEnabledAPIs(self, client=None):
        enabled_apis = []
        if self.enumerable():
            enabled_apis = client.get_enabled_apis(self['projectId'])

        self._enabled_service_names = frozenset(
            (api.get('serviceName') for api in enabled_apis))
        return enabled_apis

    def key(self):
        return self['projectId']

    def enumerable(self):
        return self['lifecycleState'] == 'ACTIVE'

    def billing_enabled(self):
        return self.getBillingInfo().get('billingEnabled', False)

    def is_api_enabled(self, service_name):
        """Returns True if the API service is enabled on the project.

        Args:
            service_name (str): The API service name to check.
        """
        return service_name in self._enabled_service_names

    def bigquery_api_enabled(self):
        # Bigquery API depends on billing being enabled
        return (self.billing_enabled() and
                self.is_api_enabled('bigquery-json.googleapis.com'))

    def cloudsql_api_enabled(self):
        # CloudSQL Admin API depends on billing being enabled
        return (self.billing_enabled() and
                self.is_api_enabled('sql-component.googleapis.com'))

    def compute_api_enabled(self):
        # Compute API depends on billing being enabled
        return (self.billing_enabled() and
                self.is_api_enabled('compute.googleapis.com'))

    def storage_api_enabled(self):
        return self.is_api_enabled('storage-component.googleapis.com')

    def type(self):
        return 'project'


class GcsBucket(Resource):
    @cached('iam_policy')
    def getIamPolicy(self, client=None):
        return client.get_bucket_iam_policy(self.key())

    def getGCSPolicy(self, client=None):
        # Full projection returns GCS policy with the resource.
        try:
            return self['acl']
        except KeyError:
            return []

    def type(self):
        return 'bucket'

    def key(self):
        return self['id']


class GcsObject(Resource):
    @cached('iam_policy')
    def getIamPolicy(self, client=None):
        return client.get_object_iam_policy(self.parent()['name'],
                                            self['name'])

    def getGCSPolicy(self, client=None):
        # Full projection returns GCS policy with the resource.
        try:
            return self['acl']
        except KeyError:
            return []

    def type(self):
        return 'storage_object'

    def key(self):
        return self['id']


class DataSet(Resource):
    @cached('dataset_policy')
    def getDatasetPolicy(self, client=None):
        return client.get_dataset_dataset_policy(
            self.parent().key(),
            self['datasetReference']['datasetId'])

    def key(self):
        return self['id']

    def type(self):
        return 'dataset'


class AppEngineApp(Resource):
    def key(self):
        # Apps do not have globally unique IDs, use size_t hash of name
        return '%u' % ctypes.c_size_t(hash(self['name'])).value

    def type(self):
        return 'appengine_app'


class AppEngineService(Resource):
    def key(self):
        # Services do not have globally unique IDs, use size_t hash of name
        return '%u' % ctypes.c_size_t(hash(self['name'])).value

    def type(self):
        return 'appengine_service'


class AppEngineVersion(Resource):
    def key(self):
        # Versions do not have globally unique IDs, use size_t hash of name
        return '%u' % ctypes.c_size_t(hash(self['name'])).value

    def type(self):
        return 'appengine_version'


class AppEngineInstance(Resource):
    def key(self):
        # Instances do not have globally unique IDs, use size_t hash of name
        return '%u' % ctypes.c_size_t(hash(self['name'])).value

    def type(self):
        return 'appengine_instance'


class ComputeProject(Resource):
    def key(self):
        return self['id']

    def type(self):
        return 'compute_project'


class Instance(Resource):
    def key(self):
        return self['id']

    def type(self):
        return 'instance'


class Firewall(Resource):
    def key(self):
        return self['id']

    def type(self):
        return 'firewall'


class Image(Resource):
    def key(self):
        return self['id']

    def type(self):
        return 'image'


class InstanceGroup(Resource):
    def key(self):
        return self['id']

    def type(self):
        return 'instancegroup'


class InstanceGroupManager(Resource):
    def key(self):
        return self['id']

    def type(self):
        return 'instancegroupmanager'


class InstanceTemplate(Resource):
    def key(self):
        return self['id']

    def type(self):
        return 'instancetemplate'


class Network(Resource):
    def key(self):
        return self['id']

    def type(self):
        return 'network'


class Subnetwork(Resource):
    def key(self):
        return self['id']

    def type(self):
        return 'subnetwork'


class BackendService(Resource):
    def key(self):
        return self['id']

    def type(self):
        return 'backendservice'


class ForwardingRule(Resource):
    def key(self):
        return self['id']

    def type(self):
        return 'forwardingrule'


class CuratedRole(Resource):
    def key(self):
        return self['name']

    def type(self):
        return 'role'

    def parent(self):
        # Curated roles have no parent.
        return None


class Role(Resource):
    def key(self):
        return self['name']

    def type(self):
        return 'role'


class CloudSqlInstance(Resource):
    def key(self):
        return self['name']

    def type(self):
        return 'cloudsqlinstance'


class ServiceAccount(Resource):
    @cached('iam_policy')
    def getIamPolicy(self, client=None):
        return client.get_serviceaccount_iam_policy(self['name'])

    def key(self):
        return self['uniqueId']

    def type(self):
        return 'serviceaccount'


class ServiceAccountKey(Resource):
    def key(self):
        # Key name is in the format:
        # projects/{project_id}/serviceAccounts/{service_account}/keys/{key_id}
        return self['name'].split('/')[-1]

    def type(self):
        return 'serviceaccount_key'


class GsuiteUser(Resource):
    def key(self):
        return self['id']

    def type(self):
        return 'gsuite_user'


class GsuiteGroup(Resource):
    def key(self):
        return self['id']

    def type(self):
        return 'gsuite_group'


class GsuiteUserMember(Resource):
    def key(self):
        return self['id']

    def type(self):
        return 'gsuite_user_member'


class GsuiteGroupMember(Resource):
    def key(self):
        return self['id']

    def type(self):
        return 'gsuite_group_member'


class ResourceIterator(object):
    def __init__(self, resource, client):
        self.resource = resource
        self.client = client

    def iter(self):
        raise NotImplementedError()


class FolderIterator(ResourceIterator):
    def iter(self):
        gcp = self.client
        for data in gcp.iter_folders(parent_id=self.resource['name']):
            yield FACTORIES['folder'].create_new(data)


class FolderFolderIterator(ResourceIterator):
    def iter(self):
        gcp = self.client
        for data in gcp.iter_folders(parent_id=self.resource['name']):
            yield FACTORIES['folder'].create_new(data)


class ProjectIterator(ResourceIterator):
    def iter(self):
        gcp = self.client
        orgid = self.resource['name'].split('/', 1)[-1]
        for data in gcp.iter_projects(parent_type='organization',
                                      parent_id=orgid):
            yield FACTORIES['project'].create_new(data)


class FolderProjectIterator(ResourceIterator):
    def iter(self):
        gcp = self.client
        folderid = self.resource['name'].split('/', 1)[-1]
        for data in gcp.iter_projects(parent_type='folder',
                                      parent_id=folderid):
            yield FACTORIES['project'].create_new(data)


class BucketIterator(ResourceIterator):
    def iter(self):
        gcp = self.client
        if self.resource.storage_api_enabled():
            for data in gcp.iter_buckets(
                    projectid=self.resource['projectNumber']):
                yield FACTORIES['bucket'].create_new(data)


class ObjectIterator(ResourceIterator):
    def iter(self):
        gcp = self.client
        for data in gcp.iter_objects(bucket_id=self.resource['id']):
            yield FACTORIES['object'].create_new(data)


class DataSetIterator(ResourceIterator):
    def iter(self):
        gcp = self.client
        if self.resource.bigquery_api_enabled():
            for data in gcp.iter_datasets(
                    projectid=self.resource['projectNumber']):
                yield FACTORIES['dataset'].create_new(data)


class AppEngineAppIterator(ResourceIterator):
    def iter(self):
        gcp = self.client
        if self.resource.enumerable():
            data = gcp.fetch_gae_app(projectid=self.resource['projectId'])
            if data:
                yield FACTORIES['appengine_app'].create_new(data)


class AppEngineServiceIterator(ResourceIterator):
    def iter(self):
        gcp = self.client
        for data in gcp.iter_gae_services(projectid=self.resource['id']):
            yield FACTORIES['appengine_service'].create_new(data)


class AppEngineVersionIterator(ResourceIterator):
    def iter(self):
        gcp = self.client
        for data in gcp.iter_gae_versions(
                projectid=self.resource.parent()['id'],
                serviceid=self.resource['id']):
            yield FACTORIES['appengine_version'].create_new(data)


class AppEngineInstanceIterator(ResourceIterator):
    def iter(self):
        gcp = self.client
        for data in gcp.iter_gae_instances(
                projectid=self.resource.parent().parent()['id'],
                serviceid=self.resource.parent()['id'],
                versionid=self.resource['id']):
            yield FACTORIES['appengine_instance'].create_new(data)


class ComputeIterator(ResourceIterator):
    def iter(self):
        gcp = self.client
        if self.resource.compute_api_enabled():
            data = gcp.fetch_compute_project(
                projectid=self.resource['projectId'])
            yield FACTORIES['compute'].create_new(data)


class InstanceIterator(ResourceIterator):
    def iter(self):
        gcp = self.client
        if self.resource.compute_api_enabled():
            for data in gcp.iter_computeinstances(
                    projectid=self.resource['projectId']):
                yield FACTORIES['instance'].create_new(data)


class FirewallIterator(ResourceIterator):
    def iter(self):
        gcp = self.client
        if self.resource.compute_api_enabled():
            for data in gcp.iter_computefirewalls(
                    projectid=self.resource['projectId']):
                yield FACTORIES['firewall'].create_new(data)


class ImageIterator(ResourceIterator):
    def iter(self):
        gcp = self.client
        if self.resource.compute_api_enabled():
            for data in gcp.iter_images(
                    projectid=self.resource['projectId']):
                yield FACTORIES['image'].create_new(data)


class InstanceGroupIterator(ResourceIterator):
    def iter(self):
        gcp = self.client
        if self.resource.compute_api_enabled():
            for data in gcp.iter_computeinstancegroups(
                    projectid=self.resource['projectId']):
                yield FACTORIES['instancegroup'].create_new(data)


class InstanceGroupManagerIterator(ResourceIterator):
    def iter(self):
        gcp = self.client
        if self.resource.compute_api_enabled():
            for data in gcp.iter_ig_managers(
                    projectid=self.resource['projectId']):
                yield FACTORIES['instancegroupmanager'].create_new(data)


class InstanceTemplateIterator(ResourceIterator):
    def iter(self):
        gcp = self.client
        if self.resource.compute_api_enabled():
            for data in gcp.iter_instancetemplates(
                    projectid=self.resource['projectId']):
                yield FACTORIES['instancetemplate'].create_new(data)


class NetworkIterator(ResourceIterator):
    def iter(self):
        gcp = self.client
        if self.resource.compute_api_enabled():
            for data in gcp.iter_networks(
                    projectid=self.resource['projectId']):
                yield FACTORIES['network'].create_new(data)


class SubnetworkIterator(ResourceIterator):
    def iter(self):
        gcp = self.client
        if self.resource.compute_api_enabled():
            for data in gcp.iter_subnetworks(
                    projectid=self.resource['projectId']):
                yield FACTORIES['subnetwork'].create_new(data)


class BackendServiceIterator(ResourceIterator):
    def iter(self):
        gcp = self.client
        if self.resource.compute_api_enabled():
            for data in gcp.iter_backendservices(
                    projectid=self.resource['projectId']):
                yield FACTORIES['backendservice'].create_new(data)


class ForwardingRuleIterator(ResourceIterator):
    def iter(self):
        gcp = self.client
        if self.resource.compute_api_enabled():
            for data in gcp.iter_forwardingrules(
                    projectid=self.resource['projectId']):
                yield FACTORIES['forwardingrule'].create_new(data)


class CloudSqlIterator(ResourceIterator):
    def iter(self):
        gcp = self.client
        if self.resource.cloudsql_api_enabled():
            for data in gcp.iter_cloudsqlinstances(
                    projectid=self.resource['projectId']):
                yield FACTORIES['cloudsqlinstance'].create_new(data)


class ServiceAccountIterator(ResourceIterator):
    def iter(self):
        gcp = self.client
        if self.resource.enumerable():
            for data in gcp.iter_serviceaccounts(
                    projectid=self.resource['projectId']):
                yield FACTORIES['serviceaccount'].create_new(data)


class ServiceAccountKeyIterator(ResourceIterator):
    def iter(self):
        gcp = self.client
        for data in gcp.iter_serviceaccount_exported_keys(
                name=self.resource['name']):
            yield FACTORIES['serviceaccount_key'].create_new(data)


class ProjectRoleIterator(ResourceIterator):
    def iter(self):
        gcp = self.client
        if self.resource.enumerable():
            for data in gcp.iter_project_roles(
                    projectid=self.resource['projectId']):
                yield FACTORIES['role'].create_new(data)


class OrganizationRoleIterator(ResourceIterator):
    def iter(self):
        gcp = self.client
        for data in gcp.iter_organization_roles(
                orgid=self.resource['name']):
            yield FACTORIES['role'].create_new(data)


class OrganizationCuratedRoleIterator(ResourceIterator):
    def iter(self):
        gcp = self.client
        for data in gcp.iter_curated_roles():
            yield FACTORIES['curated_role'].create_new(data)


class GsuiteGroupIterator(ResourceIterator):
    def iter(self):
        gsuite = self.client
        for data in gsuite.iter_groups(
                self.resource['owner']['directoryCustomerId']):
            yield FACTORIES['gsuite_group'].create_new(data)


class GsuiteUserIterator(ResourceIterator):
    def iter(self):
        gsuite = self.client
        for data in gsuite.iter_users(
                self.resource['owner']['directoryCustomerId']):
            yield FACTORIES['gsuite_user'].create_new(data)


class GsuiteMemberIterator(ResourceIterator):
    def iter(self):
        gsuite = self.client
        for data in gsuite.iter_group_members(self.resource['id']):
            if data['type'] == 'USER':
                yield FACTORIES['gsuite_user_member'].create_new(data)
            elif data['type'] == 'GROUP':
                yield FACTORIES['gsuite_group_member'].create_new(data)


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
            ProjectIterator,
            ]}),

    'folder': ResourceFactory({
        'dependsOn': ['organization'],
        'cls': Folder,
        'contains': [
            FolderFolderIterator,
            FolderProjectIterator
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
            ComputeIterator,
            ImageIterator,
            InstanceIterator,
            FirewallIterator,
            InstanceGroupIterator,
            InstanceGroupManagerIterator,
            InstanceTemplateIterator,
            BackendServiceIterator,
            ForwardingRuleIterator,
            NetworkIterator,
            SubnetworkIterator,
            ProjectRoleIterator
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

    'compute': ResourceFactory({
        'dependsOn': ['project'],
        'cls': ComputeProject,
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
    }
