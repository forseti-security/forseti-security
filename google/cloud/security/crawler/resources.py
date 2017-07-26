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
    def __init__(self, data, **kwargs):
        self._data = data
        self._stack = None

    def key(self):
        raise NotImplementedError()

    def accept(self, visitor, stack=[]):
        self._stack = stack
        visitor.visit(self)
        for child in self._iter_children():
            child.accept(visitor, stack+[self])

    def _iter_children(self):
        raise NotImplementedError()

    def _retrieve_iam_policy(self):
        raise NotImplementedError()

    def _retrieve_gcs_policy(self):
        raise NotImplementedError()

    def _stack(self):
        if self._stack is None:
            raise Exception('Stack not initialized yet')
        return self._stack


class Organization(Resource):
    @classmethod
    def fetch(cls, resource_key):
        raise NotImplementedError('not *yet* implemented')

    def _iter_children(self):
        raise NotImplementedError('not *yet* implemented')

    def _iter_projects(self):
        raise NotImplementedError('not *yet* implemented')

    def _iter_folders(self):
        raise NotImplementedError('not *yet* implemented')

    def retrieve_meta(self):
        raise NotImplementedError('not *yet* implemented')


class Folder(Resource):
    pass


class Project(Resource):
    pass


class Bucket(Resource):
    pass


class GcsObject(Resource):
    pass


RESOURCES = {

        'organization': ResourceFactory({
                'dependsOn': [],
                'hasIamPolicy': True,
                'hasGcsPolicy': False,
                'isLeaf': False,
                'cls': Organization,
            }),

        'folder': ResourceFactory({
                'dependsOn': ['organization'],
                'hasIamPolicy': True,
                'hasGcsPolicy': False,
                'isLeaf': False,
                'cls': Folder,
            }),

        'project': ResourceFactory({
                'dependsOn': ['organization', 'folder'],
                'hasIamPolicy': True,
                'hasGcsPolicy': False,
                'isLeaf': False,
                'cls': Project,
            }),

        'bucket': ResourceFactory({
                'dependsOn': ['project'],
                'hasIamPolicy': True,
                'hasGcsPolicy': True,
                'isLeaf': False,
                'cls': Bucket,
            }),
        'object': ResourceFactory({
                'dependsOn': ['bucket'],
                'hasIamPolicy': True,
                'hasGcsPolicy': True,
                'isLeaf': True,
                'cls': GcsObject,
            })

    }
