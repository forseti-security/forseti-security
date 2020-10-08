"""Tests for google.services.inventory.cai_temporary_storage."""

from future import standard_library
standard_library.install_aliases()
from io import StringIO
import unittest

from tests.unittest_utils import ForsetiTestCase

from google.cloud.forseti.services.inventory.base.gcp import AssetMetadata
from google.cloud.forseti.services.inventory import cai_temporary_storage

class CaiTemporaryStoreTest(ForsetiTestCase):
    """Test the CaiTemporaryStore table and DAO."""

    def setUp(self):
        """Setup method."""
        ForsetiTestCase.setUp(self)
        self.engine, self.dbfile = cai_temporary_storage.create_sqlite_db()

    def _add_resources(self):
        """Add CAI resources to temporary table."""
        resource_data = StringIO(CAI_RESOURCE_DATA)
        rows = cai_temporary_storage.CaiDataAccess.populate_cai_data(
            resource_data, self.engine)
        expected_rows = len(CAI_RESOURCE_DATA.split('\n'))
        self.assertEqual(expected_rows, rows)

    def _add_iam_policies(self):
        """Add CAI IAM Policies to temporary table."""
        iam_policy_data = StringIO(CAI_IAM_POLICY_DATA)
        rows = cai_temporary_storage.CaiDataAccess.populate_cai_data(
            iam_policy_data, self.engine)
        expected_rows = len(CAI_IAM_POLICY_DATA.split('\n'))
        self.assertEqual(expected_rows, rows)

    def test_populate_cai_data(self):
        """Validate CAI data insert."""
        self._add_resources()
        self._add_iam_policies()

    def test_clear_cai_data(self):
        """Validate CAI data delete."""
        self._add_resources()

        rows = cai_temporary_storage.CaiDataAccess.clear_cai_data(self.engine)
        expected_rows = len(CAI_RESOURCE_DATA.split('\n'))
        self.assertEqual(expected_rows, rows)

        results = cai_temporary_storage.CaiDataAccess.iter_cai_assets(
            cai_temporary_storage.ContentTypes.resource,
            'cloudresourcemanager.googleapis.com/Folder',
            '//cloudresourcemanager.googleapis.com/organizations/1234567890',
            self.engine)
        self.assertEqual(0, len(list(results)))

    def test_iter_cai_assets(self):
        """Validate querying CAI asset data."""
        self._add_resources()

        cai_type = 'cloudresourcemanager.googleapis.com/Folder'

        results = cai_temporary_storage.CaiDataAccess.iter_cai_assets(
            cai_temporary_storage.ContentTypes.resource,
            cai_type,
            '//cloudresourcemanager.googleapis.com/organizations/1234567890',
            self.engine)

        expected_results = [
            ('folders/11111',
             AssetMetadata(
                 cai_type=cai_type,
                 cai_name='//cloudresourcemanager.googleapis.com/folders/11111')
             )
        ]
        self.assertEqual(expected_results,
                         [(asset['name'], metadata)
                          for asset, metadata in results])

        cai_type = 'appengine.googleapis.com/Service'

        results = cai_temporary_storage.CaiDataAccess.iter_cai_assets(
            cai_temporary_storage.ContentTypes.resource,
            cai_type,
            '//appengine.googleapis.com/apps/forseti-test-project',
            self.engine)

        expected_results = [
          ('apps/forseti-test-project/services/default',
           AssetMetadata(
               cai_name=('//appengine.googleapis.com/apps/forseti-test-project/'
                         'services/default'),
               cai_type=cai_type))]
        self.assertEqual(expected_results,
                         [(asset['name'], metadata)
                          for asset, metadata in results])

    def test_fetch_cai_asset(self):
        """Validate querying single CAI asset."""
        self._add_iam_policies()

        cai_type = 'cloudresourcemanager.googleapis.com/Organization'
        cai_name = ('//cloudresourcemanager.googleapis.com/organizations/'
                    '1234567890')

        results = cai_temporary_storage.CaiDataAccess.fetch_cai_asset(
            cai_temporary_storage.ContentTypes.iam_policy,
            cai_type,
            cai_name,
            self.engine)
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
        self.assertEqual((expected_iam_policy,
                          AssetMetadata(cai_type=cai_type, cai_name=cai_name)),
                         results)



CAI_RESOURCE_DATA = """{"name":"//cloudresourcemanager.googleapis.com/organizations/1234567890","asset_type":"cloudresourcemanager.googleapis.com/Organization","resource":{"version":"v1beta1","discovery_document_uri":"https://cloudresourcemanager.googleapis.com/$discovery/rest","discovery_name":"Organization","data":{"creationTime":"2016-09-02T18:55:58.783Z","displayName":"test.forseti","lastModifiedTime":"2017-02-14T05:43:45.012Z","lifecycleState":"ACTIVE","name":"organizations/1234567890","organizationId":"1234567890","owner":{"directoryCustomerId":"C00h00n00"}}},"update_time":"2020-02-27T14:00:00Z"}
{"name":"//cloudresourcemanager.googleapis.com/folders/11111","asset_type":"cloudresourcemanager.googleapis.com/Folder","resource":{"version":"v2alpha1","discovery_document_uri":"https://cloudresourcemanager.googleapis.com/$discovery/rest","discovery_name":"Folder","parent":"//cloudresourcemanager.googleapis.com/organizations/1234567890","data":{"createTime":"2017-05-15T17:48:13.407Z","displayName":"test-folder-11111","lifecycleState":"ACTIVE","name":"folders/11111","parent":"organizations/1234567890"}},"update_time":"2020-02-27T14:00:00Z"}
{"name":"//cloudresourcemanager.googleapis.com/folders/22222","asset_type":"cloudresourcemanager.googleapis.com/Folder","resource":{"version":"v2alpha1","discovery_document_uri":"https://cloudresourcemanager.googleapis.com/$discovery/rest","discovery_name":"Folder","parent":"//cloudresourcemanager.googleapis.com/folders/11111","data":{"createTime":"2017-05-15T17:48:13.407Z","displayName":"test-folder-22222","lifecycleState":"ACTIVE","name":"folders/22222","parent":"folders/11111"}},"update_time":"2020-02-27T14:00:00Z"}
{"name":"//cloudresourcemanager.googleapis.com/projects/33333","asset_type":"cloudresourcemanager.googleapis.com/Project","resource":{"version":"v1beta1","discovery_document_uri":"https://cloudresourcemanager.googleapis.com/$discovery/rest","discovery_name":"Project","parent":"//cloudresourcemanager.googleapis.com/organizations/1234567890","data":{"createTime":"2018-03-30T17:22:52.497Z","labels":{"cost-center":"123456"},"lifecycleState":"ACTIVE","name":"forseti test project","parent":{"id":"1234567890","type":"organization"},"projectId":"forseti-test-project","projectNumber":"33333"}},"update_time":"2020-02-27T14:00:00Z"}
{"name":"//cloudresourcemanager.googleapis.com/projects/44444","asset_type":"cloudresourcemanager.googleapis.com/Project","resource":{"version":"v1beta1","discovery_document_uri":"https://cloudresourcemanager.googleapis.com/$discovery/rest","discovery_name":"Project","parent":"//cloudresourcemanager.googleapis.com/folders/22222","data":{"createTime":"2017-08-17T00:50:56.09Z","lifecycleState":"ACTIVE","name":"forseti-test-2","parent":{"id":"22222","type":"folder"},"projectId":"forseti-test-44444","projectNumber":"44444"}},"update_time":"2020-02-27T14:00:00Z"}
{"name":"//storage.googleapis.com/bucket-test-55555","asset_type":"storage.googleapis.com/Bucket","resource":{"version":"v1","discovery_document_uri":"https://www.googleapis.com/discovery/v1/apis/storage/v1/rest","discovery_name":"Bucket","parent":"//cloudresourcemanager.googleapis.com/projects/44444","data":{"acl":[],"billing":{},"cors":[],"defaultObjectAcl":[],"encryption":{},"etag":"CAE=","id":"bucket-test-55555","kind":"storage#bucket","labels":{},"lifecycle":{"rule":[]},"location":"US","logging":{},"metageneration":1,"name":"bucket-test-55555","owner":{},"projectNumber":44444,"retentionPolicy":{},"selfLink":"https://www.googleapis.com/storage/v1/b/bucket-test-55555","storageClass":"STANDARD","timeCreated":"2018-08-29T01:37:30.689Z","updated":"2018-08-29T01:37:30.689Z","versioning":{},"website":{}}},"update_time":"2020-02-27T14:00:00Z"}
{"name":"//storage.googleapis.com/Bucket-Test-55555","asset_type":"storage.googleapis.com/Bucket","resource":{"version":"v1","discovery_document_uri":"https://www.googleapis.com/discovery/v1/apis/storage/v1/rest","discovery_name":"Bucket","parent":"//cloudresourcemanager.googleapis.com/projects/44444","data":{"acl":[],"billing":{},"cors":[],"defaultObjectAcl":[],"encryption":{},"etag":"CAE=","id":"Bucket-Test-55555","kind":"storage#bucket","labels":{},"lifecycle":{"rule":[]},"location":"US","logging":{},"metageneration":1,"name":"Bucket-Test-55555","owner":{},"projectNumber":44444,"retentionPolicy":{},"selfLink":"https://www.googleapis.com/storage/v1/b/Bucket-Test-55555","storageClass":"STANDARD","timeCreated":"2018-08-29T01:37:30.689Z","updated":"2018-08-29T02:37:30.689Z","versioning":{},"website":{}}},"update_time":"2020-02-27T14:00:00Z"}
{"name":"//appengine.googleapis.com/apps/forseti-test-project","asset_type":"appengine.googleapis.com/Application","resource":{"version":"v1","discovery_document_uri":"https://www.googleapis.com/discovery/v1/apis/appengine/v1/rest","discovery_name":"Application","parent":"//cloudresourcemanager.googleapis.com/projects/33333","data":{"authDomain":"gmail.com","codeBucket":"staging.forseti-test-project.testing","defaultBucket":"forseti-test-project.testing","defaultHostname":"forseti-test-project.testing","gcrDomain":"us.gcr.io","id":"forseti-test-project","locationId":"us-central","name":"apps/forseti-test-project","servingStatus":"SERVING"}},"update_time":"2020-02-27T14:00:00Z"}
{"name":"//appengine.googleapis.com/apps/forseti-test-project/services/default","asset_type":"appengine.googleapis.com/Service","resource":{"version":"v1","discovery_document_uri":"https://www.googleapis.com/discovery/v1/apis/appengine/v1/rest","discovery_name":"Service","data":{"id":"default","name":"apps/forseti-test-project/services/default","split":{"allocations":{"20161228t180613":1}}}},"update_time":"2020-02-27T14:00:00Z"}
{"name":"//appengine.googleapis.com/apps/forseti-test-project/services/default/versions/20161228t180613","asset_type":"appengine.googleapis.com/Version","resource":{"version":"v1","discovery_document_uri":"https://www.googleapis.com/discovery/v1/apis/appengine/v1/rest","discovery_name":"Version","data":{"automaticScaling":{"coolDownPeriod":"120s","cpuUtilization":{"targetUtilization":0.5},"maxTotalInstances":20,"minTotalInstances":2},"betaSettings":{"has_docker_image":"true","module_yaml_path":"app.yaml"},"createTime":"2016-12-29T02:07:12Z","deployment":{"container":{"image":"us.gcr.io/forseti-test-project/appengine/default.20161228t180613@sha256:b48abad1caa549dd03070e53d1124f9474ac20472c7f61ee14d653d0a2ae2a5e"}},"envVariables":{"POLICY_SCANNER_DATAFLOW_TMP_BUCKET":"forseti-test-project.testing","POLICY_SCANNER_INPUT_REPOSITORY_URL":"forseti-test-project.testing","POLICY_SCANNER_ORG_ID":"1234567890","POLICY_SCANNER_ORG_NAME":"Forseti Test","POLICY_SCANNER_SINK_URL":"gs://forseti-test-project.testing/OUTPUT","PROJECT_ID":"forseti-test-project"},"id":"20161228t180613","name":"apps/forseti-test-project/services/default/versions/20161228t180613","runtime":"java","runtimeApiVersion":"1.0","servingStatus":"SERVING","threadsafe":true,"versionUrl":"https://20161228t180613-dot-forseti-test-project.testing","vm":true}},"update_time":"2020-02-27T14:00:00Z"}"""

CAI_IAM_POLICY_DATA = """{"name":"//cloudresourcemanager.googleapis.com/folders/11111","asset_type":"cloudresourcemanager.googleapis.com/Folder","iam_policy":{"etag":"BwVvLqcT+M4=","bindings":[{"role":"roles/resourcemanager.folderAdmin","members":["user:user1@test.forseti"]},{"role":"roles/resourcemanager.folderEditor","members":["serviceAccount:forseti-server-gcp-d9fffac@forseti-test-project.iam.gserviceaccount.com","user:user1@test.forseti"]}]},"update_time":"2020-02-27T14:00:00Z"}
{"name":"//cloudresourcemanager.googleapis.com/folders/22222","asset_type":"cloudresourcemanager.googleapis.com/Folder","iam_policy":{"etag":"BwVvLqcT+M4=","bindings":[{"role":"roles/resourcemanager.folderAdmin","members":["user:user1@test.forseti"]},{"role":"roles/resourcemanager.folderEditor","members":["serviceAccount:forseti-server-gcp-d9fffac@forseti-test-project.iam.gserviceaccount.com","user:user1@test.forseti"]}]},"update_time":"2020-02-27T14:00:00Z"}
{"name":"//cloudresourcemanager.googleapis.com/projects/33333","asset_type":"cloudresourcemanager.googleapis.com/Project","iam_policy":{"etag":"BwVvLqcT+M4=","bindings":[{"role":"roles/Owner","members":["user:user1@test.forseti"]},{"role":"roles/Editor","members":["serviceAccount:forseti-server-gcp-d9fffac@forseti-test-project.iam.gserviceaccount.com","user:user1@test.forseti"]}]},"update_time":"2020-02-27T14:00:00Z"}
{"name":"//cloudresourcemanager.googleapis.com/projects/33333","asset_type":"cloudresourcemanager.googleapis.com/Project","iam_policy":{"etag":"BwVvLqcT+M4=","bindings":[{"role":"roles/Owner","members":["user:user1@test.forseti"]},{"role":"roles/Editor","members":["serviceAccount:forseti-server-gcp-d9fffac@forseti-test-project.iam.gserviceaccount.com","user:user1@test.forseti"]}]},"update_time":"2020-02-27T14:00:01Z"}
{"name":"//cloudresourcemanager.googleapis.com/projects/44444","asset_type":"cloudresourcemanager.googleapis.com/Project","iam_policy":{"etag":"BwVvLqcT+M4=","bindings":[{"role":"roles/Owner","members":["user:user1@test.forseti"]},{"role":"roles/Editor","members":["serviceAccount:forseti-server-gcp-d9fffac@forseti-test-project.iam.gserviceaccount.com","user:user1@test.forseti"]}]},"update_time":"2020-02-27T14:00:00Z"}
{"name":"//cloudresourcemanager.googleapis.com/organizations/1234567890","asset_type":"cloudresourcemanager.googleapis.com/Organization","iam_policy":{"etag":"BwVvLqcT+M4=","bindings":[{"role":"roles/Owner","members":["user:user1@test.forseti"]},{"role":"roles/Viewer","members":["serviceAccount:forseti-server-gcp-d9fffac@forseti-test-project.iam.gserviceaccount.com","user:user1@test.forseti"]}]},"update_time":"2020-02-27T14:00:00Z"}"""


if __name__ == '__main__':
    unittest.main()
