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

""" Crawler implementation. """

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
    def __init__(self, data, contains=None, isLeaf=False, **kwargs):
        self._data = data
        self._stack = None
        self._leaf = isLeaf
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

    def res_type(self):
        raise NotImplementedError()

    def parent(self):
        try:
            return self._stack[-1]
        except IndexError:
            return None

    def key(self):
        return self['id']

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

    def getIamPolicy(self, client):
        return None

    def getGCSPolicy(self, client):
        return None

    def getOrgPolicy(self, client):
        return None

    def getCloudSQLPolicy(self, client):
        return None

    def getDatasetPolicy(self, client):
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
    def getIamPolicy(self, client):
        return client.get_organization_iam_policy(self.key())

    def key(self):
        return self['name']


class Folder(Resource):
    def getIamPolicy(self, client):
        raise NotImplementedError()


class Project(Resource):

    @cached('iam_policy')
    def getIamPolicy(self, client):
        return client.get_project_iam_policy(self.key())

    def key(self):
        return self['projectId']

    def enumerable(self):
        return self['lifecycleState'] not in ['DELETE_REQUESTED']


class Bucket(Resource):
    @cached('iam_policy')
    def getIamPolicy(self, client):
        return client.get_bucket_iam_policy(self.key())

    @cached('gcs_policy')
    def getGCSPolicy(self, client):
        return client.get_bucket_gcs_policy(self.key())


class GcsObject(Resource):
    @cached('iam_policy')
    def getIamPolicy(self, client):
        return client.get_object_iam_policy(self.key())

    @cached('gcs_policy')
    def getGCSPolicy(self, client):
        return client.get_object_gcs_policy(self.key())


class DataSet(Resource):
    @cached('dataset_policy')
    def getDatasetPolicy(self, client):
        return client.get_dataset_dataset_policy(self.parent().key(),
                                                 self.key())

    def key(self):
        return self['datasetId']


class ResourceIterator(object):
    def __init__(self, resource, client):
        self.resource = resource
        self.client = client

    def iter(self):
        raise NotImplementedError()


class FolderIterator(ResourceIterator):
    def iter(self):
        gcp = self.client
        for data in gcp.iter_folders(orgid=self.resource.key()):
            yield FACTORIES['folder'].create_new(data)


class BucketIterator(ResourceIterator):
    def iter(self):
        gcp = self.client
        if self.resource.enumerable():
            for data in gcp.iter_buckets(projectid=int(self.resource['projectNumber'])):
                yield FACTORIES['bucket'].create_new(data)


class ProjectIterator(ResourceIterator):
    def iter(self):
        gcp = self.client
        for data in gcp.iter_projects(orgid=self.resource.key()):
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
            for data in gcp.iter_datasets(projectid=int(self.resource['projectNumber'])):
                yield FACTORIES['dataset'].create_new(data)

FACTORIES = {

        'organization': ResourceFactory({
                'dependsOn': [],
                'isLeaf': False,
                'cls': Organization,
                'contains': [ProjectIterator],
            }),

        'folder': ResourceFactory({
                'dependsOn': ['organization'],
                'isLeaf': False,
                'cls': Folder,
                'contains': [],
            }),

        'project': ResourceFactory({
                'dependsOn': ['organization', 'folder'],
                'isLeaf': False,
                'cls': Project,
                'contains': [BucketIterator, DataSetIterator],
            }),

        'bucket': ResourceFactory({
                'dependsOn': ['project'],
                'isLeaf': False,
                'cls': Bucket,
                'contains': [],
            }),

        'object': ResourceFactory({
                'dependsOn': ['bucket'],
                'isLeaf': True,
                'cls': GcsObject,
                'contains': [],
            }),

        'dataset': ResourceFactory({
                'dependsOn': ['project'],
                'isLeaf': True,
                'cls': DataSet,
                'contains': [],
            })

    }
