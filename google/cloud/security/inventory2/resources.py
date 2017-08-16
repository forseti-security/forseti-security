# Copyright 2017 Google Inc.
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

import json


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

    def create_new(self, data):
        attrs = self.attributes
        cls = attrs['cls']
        return cls(data, **attrs)


class ResourceKey(object):
    def __init__(self, res_type, res_id):
        self.res_type = res_type
        self.res_id = res_id


class Resource(object):
    def __init__(self, data, contains=None, **kwargs):
        self._data = data
        self._stack = None
        self._leaf = len(contains) == 0
        self._contains = [] if contains is None else contains

    def is_leaf(self):
        return self._leaf

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
        try:
            return self._stack[-1]
        except IndexError:
            return None

    def key(self):
        raise NotImplementedError('Class: {}'.format(self.__class__.__name__))

    def accept(self, visitor, stack=[]):
        self._stack = stack
        self._visitor = visitor
        visitor.visit(self)
        for yielder_cls in self._contains:
            yielder = yielder_cls(self, visitor.get_client())
            for resource in yielder.iter():
                def call_accept():
                    resource.accept(visitor, stack + [self])
                if resource.is_leaf():
                    call_accept()

                # Potential parallelization for non-leaf resources
                else:
                    visitor.dispatch(call_accept)

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

    def stack(self):
        if self._stack is None:
            raise Exception('Stack not initialized yet')
        return self._stack

    def visitor(self):
        if self._visitor is None:
            raise Exception('Visitor not initialized yet')
        return self._visitor

    def __repr__(self):
        return '{}<{}>'.format(
            self.__class__.__name__,
            json.dumps(self._data))


class Organization(Resource):
    @classmethod
    def fetch(cls, client, resource_key):
        data = client.fetch_organization(resource_key)
        return FACTORIES['organization'].create_new(data)

    @cached('iam_policy')
    def getIamPolicy(self, client=None):
        return client.get_organization_iam_policy(self['name'])

    def key(self):
        return self['name'].split('/', 1)[-1]

    def type(self):
        return 'organization'

    def parent(self):
        return self


class Folder(Resource):
    def key(self):
        return self['name'].split('/', 1)[-1]

    @cached('iam_policy')
    def getIamPolicy(self, client=None):
        return client.get_folder_iam_policy(self['name'])

    def type(self):
        return 'folder'


class Project(Resource):

    @cached('iam_policy')
    def getIamPolicy(self, client=None):
        return client.get_project_iam_policy(self['projectId'])

    def key(self):
        return self['projectId']

    def enumerable(self):
        return self['lifecycleState'] not in ['DELETE_REQUESTED']

    def type(self):
        return 'project'


class GcsBucket(Resource):
    @cached('iam_policy')
    def getIamPolicy(self, client=None):
        return client.get_bucket_iam_policy(self.key())

    @cached('gcs_policy')
    def getGCSPolicy(self, client=None):
        return client.get_bucket_gcs_policy(self.key())

    def type(self):
        return 'bucket'

    def key(self):
        return self['id']


class GcsObject(Resource):
    @cached('iam_policy')
    def getIamPolicy(self, client=None):
        return client.get_object_iam_policy(self.parent()['name'],
                                            self['name'])

    @cached('gcs_policy')
    def getGCSPolicy(self, client=None):
        return client.get_object_gcs_policy(self.parent()['name'],
                                            self['name'])

    def type(self):
        return 'storage_object'

    def key(self):
        return self['id']


class DataSet(Resource):
    @cached('dataset_policy')
    def getDatasetPolicy(self, client=None):
        return client.get_dataset_dataset_policy(self.parent().key(),
                                                 self.key())

    def key(self):
        return self['datasetId']

    def type(self):
        return 'dataset'


class AppEngineApp(Resource):
    def key(self):
        return self['name']

    def type(self):
        return 'appengineapp'


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
    def key(self):
        return self['uniqueId']

    def type(self):
        return 'serviceaccount'


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
        for data in gcp.iter_folders(orgid=self.resource['name']):
            yield FACTORIES['folder'].create_new(data)


class BucketIterator(ResourceIterator):
    def iter(self):
        gcp = self.client
        if self.resource.enumerable():
            for data in gcp.iter_buckets(
                    projectid=int(self.resource['projectNumber'])):
                yield FACTORIES['bucket'].create_new(data)


class ProjectIterator(ResourceIterator):
    def iter(self):
        gcp = self.client
        for data in gcp.iter_projects(orgid=self.resource['name']):
            yield FACTORIES['project'].create_new(data)


class ObjectIterator(ResourceIterator):
    def iter(self):
        gcp = self.client
        for data in gcp.iter_objects(bucket_id=self.resource['id']):
            yield FACTORIES['object'].create_new(data)


class DataSetIterator(ResourceIterator):
    def iter(self):
        gcp = self.client
        if self.resource.enumerable():
            for data in gcp.iter_datasets(
                    projectid=int(self.resource['projectNumber'])):
                yield FACTORIES['dataset'].create_new(data)


class AppEngineAppIterator(ResourceIterator):
    def iter(self):
        gcp = self.client
        if self.resource.enumerable():
            for data in gcp.iter_appengineapps(
                    projectid=int(self.resource['projectNumber'])):
                yield FACTORIES['appengineapp'].create_new(data)


class InstanceIterator(ResourceIterator):
    def iter(self):
        gcp = self.client
        if self.resource.enumerable():
            for data in gcp.iter_computeinstances(
                    projectid=self.resource['projectId']):
                yield FACTORIES['instance'].create_new(data)


class FirewallIterator(ResourceIterator):
    def iter(self):
        gcp = self.client
        if self.resource.enumerable():
            for data in gcp.iter_computefirewalls(
                    projectid=self.resource['projectId']):
                yield FACTORIES['firewall'].create_new(data)


class CloudSqlIterator(ResourceIterator):
    def iter(self):
        gcp = self.client
        if self.resource.enumerable():
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
        for data in gcp.iter_curated_roles(orgid=self.resource['name']):
            yield FACTORIES['role'].create_new(data)


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
                             ],
            }),

        'folder': ResourceFactory({
                'dependsOn': ['organization'],
                'cls': Folder,
                'contains': [],
            }),

        'project': ResourceFactory({
                'dependsOn': ['organization', 'folder'],
                'cls': Project,
                'contains': [#AppEngineAppIterator,
                             BucketIterator,
                             DataSetIterator,
                             InstanceIterator,
                             FirewallIterator,
                             CloudSqlIterator,
                             ServiceAccountIterator,
                             ProjectRoleIterator,
                             ],
            }),

        'bucket': ResourceFactory({
                'dependsOn': ['project'],
                'cls': GcsBucket,
                'contains': [
                             ObjectIterator
                             ],
            }),

        'object': ResourceFactory({
                'dependsOn': ['bucket'],
                'cls': GcsObject,
                'contains': [],
            }),

        'dataset': ResourceFactory({
                'dependsOn': ['project'],
                'cls': DataSet,
                'contains': [],
            }),

        'appengineapp': ResourceFactory({
                'dependsOn': ['project'],
                'cls': AppEngineApp,
                'contains': [],
            }),

        'instance': ResourceFactory({
                'dependsOn': ['project'],
                'cls': Instance,
                'contains': [],
            }),

        'firewall': ResourceFactory({
                'dependsOn': ['project'],
                'cls': Firewall,
                'contains': [],
            }),

        'cloudsqlinstance': ResourceFactory({
                'dependsOn': ['project'],
                'cls': CloudSqlInstance,
                'contains': [],
            }),

        'serviceaccount': ResourceFactory({
                'dependsOn': ['project'],
                'cls': ServiceAccount,
                'contains': [],
            }),

        'role': ResourceFactory({
                'dependsOn': ['project'],
                'cls': Role,
                'contains': [],
            }),

        'gsuite_user': ResourceFactory({
                'dependsOn': ['organization'],
                'cls': GsuiteUser,
                'contains': [],
            }),

        'gsuite_group': ResourceFactory({
                'dependsOn': ['organization'],
                'cls': GsuiteGroup,
                'contains': [
                            GsuiteMemberIterator,
                            ],
            }),

        'gsuite_user_member': ResourceFactory({
                'dependsOn': ['gsuite_group'],
                'cls': GsuiteUserMember,
                'contains': [],
            }),

        'gsuite_group_member': ResourceFactory({
                'dependsOn': ['gsuite_group'],
                'cls': GsuiteGroupMember,
                'contains': [],
            }),
    }
