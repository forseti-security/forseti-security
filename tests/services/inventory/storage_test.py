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
"""Unit Tests: Inventory storage for Forseti Server."""


from datetime import datetime
import mock
import os
from StringIO import StringIO
import unittest
from sqlalchemy.orm import sessionmaker

from tests.services.util.db import create_test_engine
from tests.services.util.db import create_test_engine_with_file
from tests.unittest_utils import ForsetiTestCase

from google.cloud.forseti.services import db
from google.cloud.forseti.services.inventory.base.resources import Resource
from google.cloud.forseti.services.inventory.storage import CaiDataAccess
from google.cloud.forseti.services.inventory.storage import ContentTypes
from google.cloud.forseti.services.inventory.storage import initialize
from google.cloud.forseti.services.inventory.storage import InventoryIndex
from google.cloud.forseti.services.inventory.storage import Storage


class ResourceMock(Resource):

    def __init__(self, key, data, res_type, category, parent=None, warning=[]):
        self._key = key
        self._data = data
        self._res_type = res_type
        self._catetory = category
        self._parent = parent if parent else self
        self._warning = warning
        self._contains = []
        self._timestamp = self._utcnow()
        self._inventory_key = None

    def type(self):
        return self._res_type

    def key(self):
        return self._key

    def parent(self):
        return self._parent


class StorageTest(ForsetiTestCase):
    """Test inventory storage."""

    def setUp(self):
        """Setup method."""
        ForsetiTestCase.setUp(self)

    def tearDown(self):
        """Tear down method."""
        ForsetiTestCase.tearDown(self)

    def reduced_inventory(self, storage, types):
        result = (
            [x for x in storage.iter(types)])
        return result

    def test_basic(self):
        """Test storing a few resources, then iterate."""
        engine = create_test_engine()

        initialize(engine)
        scoped_sessionmaker = db.create_scoped_sessionmaker(engine)

        res_org = ResourceMock('1', {'id': 'test'}, 'organization', 'resource')
        res_proj1 = ResourceMock('2', {'id': 'test'}, 'project', 'resource',
                                 res_org)
        res_proj1 = ResourceMock('2', {'id': 'test'}, 'project', 'iam_policy',
                                 res_proj1)
        res_proj1 = ResourceMock('2', {'id': 'test'}, 'project', 'billing_info',
                                 res_proj1)
        res_buc1 = ResourceMock('3', {'id': 'test'}, 'bucket', 'resource',
                                res_proj1)
        res_proj2 = ResourceMock('4', {'id': 'test'}, 'project', 'resource',
                                 res_org)
        res_buc2 = ResourceMock('5', {'id': 'test'}, 'bucket', 'resource',
                                res_proj2)
        res_obj2 = ResourceMock('6', {'id': 'test'}, 'object', 'resource',
                                res_buc2)

        resources = [
            res_org,
            res_proj1,
            res_buc1,
            res_proj2,
            res_buc2,
            res_obj2
        ]

        with scoped_sessionmaker() as session:
            with Storage(session) as storage:
                for resource in resources:
                    storage.write(resource)
                storage.commit()

                self.assertEqual(3,
                                 len(self.reduced_inventory(
                                     storage,
                                     ['organization', 'bucket'])),
                                 'Only 1 organization and 2 buckets')

                self.assertEqual(6,
                                 len(self.reduced_inventory(storage, [])),
                                 'No types should yield empty list')

        with scoped_sessionmaker() as session:
            storage = Storage(session)
            _ = storage.open()
            for resource in resources:
                storage.write(resource)
            storage.buffer.flush()
            self.assertEqual(3,
                             len(self.reduced_inventory(
                                 storage,
                                 ['organization', 'bucket'])),
                             'Only 1 organization and 2 buckets')

            self.assertEqual(6,
                             len(self.reduced_inventory(storage, [])),
                             'No types should yield empty list')


    def test_storage_with_timestamps(self):
        """Crawl from project, verify every resource has a timestamp."""

        def verify_resource_timestamps_from_storage(storage):
            for i, item in enumerate(storage.iter(list()), start=1):
                self.assertTrue('timestamp' in item.get_other())
            return i

        engine = create_test_engine()

        initialize(engine)
        scoped_sessionmaker = db.create_scoped_sessionmaker(engine)

        res_org = ResourceMock('1', {'id': 'test'}, 'organization', 'resource')
        with scoped_sessionmaker() as session:
            with Storage(session) as storage:
                storage.write(res_org)
                storage.commit()

                resource_count = (
                    verify_resource_timestamps_from_storage(storage))
                self.assertEqual(1, resource_count,
                                 'Unexpected number of resources in inventory')


class InventoryIndexTest(ForsetiTestCase):
    """Test inventory storage."""

    def setUp(self):
        """Setup method."""
        ForsetiTestCase.setUp(self)
        self.fake_utcnow = datetime(year=1910, month=9, day=8, hour=7, minute=6)
        self.engine, self.dbfile = create_test_engine_with_file()
        _session_maker = sessionmaker()
        self.session = _session_maker(bind=self.engine)
        initialize(self.engine)

    def tearDown(self):
        """Tear down method."""
        os.unlink(self.dbfile)
        ForsetiTestCase.tearDown(self)

    def test_get_summary(self):
        res_org = ResourceMock('1', {'id': 'test'}, 'organization', 'resource')
        res_proj1 = ResourceMock('2', {'id': 'test'}, 'project', 'resource',
                                 res_org)
        res_proj1 = ResourceMock('3', {'id': 'test'}, 'project', 'iam_policy',
                                 res_proj1)
        res_proj1 = ResourceMock('4', {'id': 'test'}, 'project', 'billing_info',
                                 res_proj1)
        res_buc1 = ResourceMock('5', {'id': 'test'}, 'bucket', 'resource',
                                res_proj1)
        res_proj2 = ResourceMock('6', {'id': 'test'}, 'project', 'resource',
                                 res_org)
        res_buc2 = ResourceMock('7', {'id': 'test'}, 'bucket', 'resource',
                                res_proj2)
        res_obj2 = ResourceMock('8', {'id': 'test'}, 'object', 'resource',
                                res_buc2)
        resources = [
            res_org, res_proj1, res_buc1, res_proj2, res_buc2, res_obj2]

        storage = Storage(self.session)
        inv_index_id = storage.open()
        for resource in resources:
            storage.write(resource)
        storage.commit()
        # add more resource data that belongs to a different inventory index
        storage = Storage(self.session)
        storage.open()
        for resource in resources:
            storage.write(resource)
        storage.commit()

        inv_index = self.session.query(InventoryIndex).get(inv_index_id)
        expected = {'bucket': 2, 'object': 1, 'organization': 1, 'project': 2}
        inv_summary = inv_index.get_summary(self.session)
        self.assertEquals(expected, inv_summary)

    @unittest.skip('The return value for query.all will leak to other tests.')
    def test_get_lifecycle_state_details_can_handle_none_result(self):
        mock_session = mock.MagicMock
        mock_session.query = mock.MagicMock
        mock_session.query.filter = mock.MagicMock
        mock_session.query.group_by = mock.MagicMock
        mock_session.query.all = mock.MagicMock
        mock_session.query.all.return_value = [None]

        inventory_index = InventoryIndex()
        details = inventory_index.get_lifecycle_state_details(mock_session,
                                                              'abc')

        self.assertEquals({}, details)


class CaiTemporaryStoreTest(ForsetiTestCase):
    """Test the CaiTemporaryStore table and DAO."""

    def setUp(self):
        """Setup method."""
        ForsetiTestCase.setUp(self)
        self.engine, self.dbfile = create_test_engine_with_file()
        _session_maker = sessionmaker()
        self.session = _session_maker(bind=self.engine)
        initialize(self.engine)

    def _add_resources(self):
        """Add CAI resources to temporary table."""
        resource_data = StringIO(CAI_RESOURCE_DATA)
        rows = CaiDataAccess.populate_cai_data(resource_data, self.session)
        expected_rows = len(CAI_RESOURCE_DATA.split('\n'))
        self.assertEqual(expected_rows, rows)

    def _add_iam_policies(self):
        """Add CAI IAM Policies to temporary table."""
        iam_policy_data = StringIO(CAI_IAM_POLICY_DATA)
        rows = CaiDataAccess.populate_cai_data(iam_policy_data, self.session)
        expected_rows = len(CAI_IAM_POLICY_DATA.split('\n'))
        self.assertEqual(expected_rows, rows)

    def test_populate_cai_data(self):
        """Validate CAI data insert."""
        self._add_resources()
        self._add_iam_policies()

    def test_clear_cai_data(self):
        """Validate CAI data delete."""
        self._add_resources()

        rows = CaiDataAccess.clear_cai_data(self.session)
        expected_rows = len(CAI_RESOURCE_DATA.split('\n'))
        self.assertEqual(expected_rows, rows)

        results = CaiDataAccess.iter_cai_assets(
            ContentTypes.resource,
            'cloudresourcemanager.googleapis.com/Folder',
            '//cloudresourcemanager.googleapis.com/organizations/1234567890',
            self.session)
        self.assertEqual(0, len(list(results)))

    def test_iter_cai_assets(self):
        """Validate querying CAI asset data."""
        self._add_resources()

        results = CaiDataAccess.iter_cai_assets(
            ContentTypes.resource,
            'cloudresourcemanager.googleapis.com/Folder',
            '//cloudresourcemanager.googleapis.com/organizations/1234567890',
            self.session)

        expected_names = ['folders/11111']
        self.assertEqual(expected_names, [asset['name'] for asset in results])

        results = CaiDataAccess.iter_cai_assets(
            ContentTypes.resource,
            'appengine.googleapis.com/Service',
            '//appengine.googleapis.com/apps/forseti-test-project',
            self.session)

        expected_names = ['apps/forseti-test-project/services/default']
        self.assertEqual(expected_names, [asset['name'] for asset in results])

    def test_fetch_cai_asset(self):
        """Validate querying single CAI asset."""
        self._add_iam_policies()

        results = CaiDataAccess.fetch_cai_asset(
            ContentTypes.iam_policy,
            'cloudresourcemanager.googleapis.com/Organization',
            '//cloudresourcemanager.googleapis.com/organizations/1234567890',
            self.session)
        expected_iam_policy = {
            'etag': 'BwVvLqcT+M4=',
            'bindings': [
                {'role': 'roles/Owner',
                 'members': ['user:user1@test.forseti']
                },
                {'role': 'roles/Viewer',
                 'members': [('serviceAccount:forseti-server-gcp-d9fffac'
                              '@forseti-test-project.iam.gserviceaccount.com'),
                             'user:user1@test.forseti']
                }
            ]
        }
        self.assertDictEqual(expected_iam_policy, results)



CAI_RESOURCE_DATA = """{"name":"//cloudresourcemanager.googleapis.com/organizations/1234567890","asset_type":"cloudresourcemanager.googleapis.com/Organization","resource":{"version":"v1beta1","discovery_document_uri":"https://cloudresourcemanager.googleapis.com/$discovery/rest","discovery_name":"Organization","data":{"creationTime":"2016-09-02T18:55:58.783Z","displayName":"test.forseti","lastModifiedTime":"2017-02-14T05:43:45.012Z","lifecycleState":"ACTIVE","name":"organizations/1234567890","organizationId":"1234567890","owner":{"directoryCustomerId":"C00h00n00"}}}}
{"name":"//cloudresourcemanager.googleapis.com/folders/11111","asset_type":"cloudresourcemanager.googleapis.com/Folder","resource":{"version":"v2alpha1","discovery_document_uri":"https://cloudresourcemanager.googleapis.com/$discovery/rest","discovery_name":"Folder","parent":"//cloudresourcemanager.googleapis.com/organizations/1234567890","data":{"createTime":"2017-05-15T17:48:13.407Z","displayName":"test-folder-11111","lifecycleState":"ACTIVE","name":"folders/11111","parent":"organizations/1234567890"}}}
{"name":"//cloudresourcemanager.googleapis.com/folders/22222","asset_type":"cloudresourcemanager.googleapis.com/Folder","resource":{"version":"v2alpha1","discovery_document_uri":"https://cloudresourcemanager.googleapis.com/$discovery/rest","discovery_name":"Folder","parent":"//cloudresourcemanager.googleapis.com/folders/11111","data":{"createTime":"2017-05-15T17:48:13.407Z","displayName":"test-folder-22222","lifecycleState":"ACTIVE","name":"folders/22222","parent":"folders/11111"}}}
{"name":"//cloudresourcemanager.googleapis.com/projects/33333","asset_type":"cloudresourcemanager.googleapis.com/Project","resource":{"version":"v1beta1","discovery_document_uri":"https://cloudresourcemanager.googleapis.com/$discovery/rest","discovery_name":"Project","parent":"//cloudresourcemanager.googleapis.com/organizations/1234567890","data":{"createTime":"2018-03-30T17:22:52.497Z","labels":{"cost-center":"123456"},"lifecycleState":"ACTIVE","name":"forseti test project","parent":{"id":"1234567890","type":"organization"},"projectId":"forseti-test-project","projectNumber":"33333"}}}
{"name":"//cloudresourcemanager.googleapis.com/projects/44444","asset_type":"cloudresourcemanager.googleapis.com/Project","resource":{"version":"v1beta1","discovery_document_uri":"https://cloudresourcemanager.googleapis.com/$discovery/rest","discovery_name":"Project","parent":"//cloudresourcemanager.googleapis.com/folders/22222","data":{"createTime":"2017-08-17T00:50:56.09Z","lifecycleState":"ACTIVE","name":"forseti-test-2","parent":{"id":"22222","type":"folder"},"projectId":"forseti-test-44444","projectNumber":"44444"}}}
{"name":"//storage.googleapis.com/bucket-test-55555","asset_type":"storage.googleapis.com/Bucket","resource":{"version":"v1","discovery_document_uri":"https://www.googleapis.com/discovery/v1/apis/storage/v1/rest","discovery_name":"Bucket","parent":"//cloudresourcemanager.googleapis.com/projects/44444","data":{"acl":[],"billing":{},"cors":[],"defaultObjectAcl":[],"encryption":{},"etag":"CAE=","id":"bucket-test-55555","kind":"storage#bucket","labels":{},"lifecycle":{"rule":[]},"location":"US","logging":{},"metageneration":1,"name":"bucket-test-55555","owner":{},"projectNumber":44444,"retentionPolicy":{},"selfLink":"https://www.googleapis.com/storage/v1/b/bucket-test-55555","storageClass":"STANDARD","timeCreated":"2018-08-29T01:37:30.689Z","updated":"2018-08-29T01:37:30.689Z","versioning":{},"website":{}}}}
{"name":"//storage.googleapis.com/Bucket-Test-55555","asset_type":"storage.googleapis.com/Bucket","resource":{"version":"v1","discovery_document_uri":"https://www.googleapis.com/discovery/v1/apis/storage/v1/rest","discovery_name":"Bucket","parent":"//cloudresourcemanager.googleapis.com/projects/44444","data":{"acl":[],"billing":{},"cors":[],"defaultObjectAcl":[],"encryption":{},"etag":"CAE=","id":"Bucket-Test-55555","kind":"storage#bucket","labels":{},"lifecycle":{"rule":[]},"location":"US","logging":{},"metageneration":1,"name":"Bucket-Test-55555","owner":{},"projectNumber":44444,"retentionPolicy":{},"selfLink":"https://www.googleapis.com/storage/v1/b/Bucket-Test-55555","storageClass":"STANDARD","timeCreated":"2018-08-29T01:37:30.689Z","updated":"2018-08-29T02:37:30.689Z","versioning":{},"website":{}}}}
{"name":"//appengine.googleapis.com/apps/forseti-test-project","asset_type":"appengine.googleapis.com/Application","resource":{"version":"v1","discovery_document_uri":"https://www.googleapis.com/discovery/v1/apis/appengine/v1/rest","discovery_name":"Application","parent":"//cloudresourcemanager.googleapis.com/projects/33333","data":{"authDomain":"gmail.com","codeBucket":"staging.forseti-test-project.testing","defaultBucket":"forseti-test-project.testing","defaultHostname":"forseti-test-project.testing","gcrDomain":"us.gcr.io","id":"forseti-test-project","locationId":"us-central","name":"apps/forseti-test-project","servingStatus":"SERVING"}}}
{"name":"//appengine.googleapis.com/apps/forseti-test-project/services/default","asset_type":"appengine.googleapis.com/Service","resource":{"version":"v1","discovery_document_uri":"https://www.googleapis.com/discovery/v1/apis/appengine/v1/rest","discovery_name":"Service","data":{"id":"default","name":"apps/forseti-test-project/services/default","split":{"allocations":{"20161228t180613":1}}}}}
{"name":"//appengine.googleapis.com/apps/forseti-test-project/services/default/versions/20161228t180613","asset_type":"appengine.googleapis.com/Version","resource":{"version":"v1","discovery_document_uri":"https://www.googleapis.com/discovery/v1/apis/appengine/v1/rest","discovery_name":"Version","data":{"automaticScaling":{"coolDownPeriod":"120s","cpuUtilization":{"targetUtilization":0.5},"maxTotalInstances":20,"minTotalInstances":2},"betaSettings":{"has_docker_image":"true","module_yaml_path":"app.yaml"},"createTime":"2016-12-29T02:07:12Z","deployment":{"container":{"image":"us.gcr.io/forseti-test-project/appengine/default.20161228t180613@sha256:b48abad1caa549dd03070e53d1124f9474ac20472c7f61ee14d653d0a2ae2a5e"}},"envVariables":{"POLICY_SCANNER_DATAFLOW_TMP_BUCKET":"forseti-test-project.testing","POLICY_SCANNER_INPUT_REPOSITORY_URL":"forseti-test-project.testing","POLICY_SCANNER_ORG_ID":"1234567890","POLICY_SCANNER_ORG_NAME":"Forseti Test","POLICY_SCANNER_SINK_URL":"gs://forseti-test-project.testing/OUTPUT","PROJECT_ID":"forseti-test-project"},"id":"20161228t180613","name":"apps/forseti-test-project/services/default/versions/20161228t180613","runtime":"java","runtimeApiVersion":"1.0","servingStatus":"SERVING","threadsafe":true,"versionUrl":"https://20161228t180613-dot-forseti-test-project.testing","vm":true}}}"""

CAI_IAM_POLICY_DATA = """{"name":"//cloudresourcemanager.googleapis.com/folders/11111","asset_type":"cloudresourcemanager.googleapis.com/Folder","iam_policy":{"etag":"BwVvLqcT+M4=","bindings":[{"role":"roles/resourcemanager.folderAdmin","members":["user:user1@test.forseti"]},{"role":"roles/resourcemanager.folderEditor","members":["serviceAccount:forseti-server-gcp-d9fffac@forseti-test-project.iam.gserviceaccount.com","user:user1@test.forseti"]}]}}
{"name":"//cloudresourcemanager.googleapis.com/folders/22222","asset_type":"cloudresourcemanager.googleapis.com/Folder","iam_policy":{"etag":"BwVvLqcT+M4=","bindings":[{"role":"roles/resourcemanager.folderAdmin","members":["user:user1@test.forseti"]},{"role":"roles/resourcemanager.folderEditor","members":["serviceAccount:forseti-server-gcp-d9fffac@forseti-test-project.iam.gserviceaccount.com","user:user1@test.forseti"]}]}}
{"name":"//cloudresourcemanager.googleapis.com/projects/33333","asset_type":"cloudresourcemanager.googleapis.com/Project","iam_policy":{"etag":"BwVvLqcT+M4=","bindings":[{"role":"roles/Owner","members":["user:user1@test.forseti"]},{"role":"roles/Editor","members":["serviceAccount:forseti-server-gcp-d9fffac@forseti-test-project.iam.gserviceaccount.com","user:user1@test.forseti"]}]}}
{"name":"//cloudresourcemanager.googleapis.com/projects/44444","asset_type":"cloudresourcemanager.googleapis.com/Project","iam_policy":{"etag":"BwVvLqcT+M4=","bindings":[{"role":"roles/Owner","members":["user:user1@test.forseti"]},{"role":"roles/Editor","members":["serviceAccount:forseti-server-gcp-d9fffac@forseti-test-project.iam.gserviceaccount.com","user:user1@test.forseti"]}]}}
{"name":"//cloudresourcemanager.googleapis.com/organizations/1234567890","asset_type":"cloudresourcemanager.googleapis.com/Organization","iam_policy":{"etag":"BwVvLqcT+M4=","bindings":[{"role":"roles/Owner","members":["user:user1@test.forseti"]},{"role":"roles/Viewer","members":["serviceAccount:forseti-server-gcp-d9fffac@forseti-test-project.iam.gserviceaccount.com","user:user1@test.forseti"]}]}}"""

if __name__ == '__main__':
    unittest.main()
