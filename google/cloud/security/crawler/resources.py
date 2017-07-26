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
        return self._data['id']

    def accept(self, visitor, stack=[]):
        self._stack = stack
        self._visitor = visitor
        self._retrieve_meta()
        visitor.visit(self)
        for child in self._iter_children():
            child.accept(visitor, stack+[self])

    def _iter_children(self):
        raise NotImplementedError()

    def _retrieve_meta(self):
        if self._visitor.should_retrieve_iam_policy():
            self._retrieve_iam_policy()
        if self._visitor.should_retrieve_gcs_policy():
            self._retrieve_gcs_policy()

    def _retrieve_iam_policy(self):
        raise NotImplementedError()

    def _retrieve_gcs_policy(self):
        raise NotImplementedError()

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

    def _iter_children(self):
        for child in self._iter_folders():
            yield child
        for child in self._iter_projects():
            yield child

    def _iter_projects(self):
        visitor = self.visitor()
        gcp = visitor.get_client()
        for project_data in gcp._iter_projects(orgid=self._data['id']):
            yield FACTORIES['project'].create_new(project_data)

    def _iter_folders(self):
        visitor = self.visitor()
        gcp = visitor.get_client()
        for folder_data in gcp._iter_folders(orgid=self._data['id']):
            yield FACTORIES['folder'].create_new(folder_data)


class Folder(Resource):
    def _iter_children(self):
        for child in self._iter_folders():
            yield child
        for child in self._iter_projects():
            yield child

    def _iter_projects(self):
        visitor = self.visitor()
        gcp = visitor.get_client()
        for project_data in gcp._iter_projects_by_folder(folderid=self._data['id']):
            yield FACTORIES['project'].create_new(project_data)

    def _iter_folders(self):
        visitor = self.visitor()
        gcp = visitor.get_client()
        for folder_data in gcp._iter_folders_by_folder(folderid=self._data['id']):
            yield FACTORIES['folder'].create_new(folder_data)


class Project(Resource):
    def _iter_children(self):
        for child in self._iter_buckets():
            yield child

    def _iter_buckets(self):
        for child in []:
            yield child


class Bucket(Resource):
    pass


class GcsObject(Resource):
    pass


FACTORIES = {

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
