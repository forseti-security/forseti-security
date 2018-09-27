# Copyright 2018 The Forseti Security Authors. All rights reserved.
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

"""Tests for RetentionScanner."""

import collections
from tests.unittest_utils import ForsetiTestCase
import mock
from google.cloud.forseti.scanner.scanners import retention_scanner

def _mock_gcp_resource_iter(_, resource_type):
    """Creates a list of GCP resource mocks retrieved by the scanner."""
    resources = []
    if resource_type != 'bucket':
        raise ValueError(
            'unexpected resource type: got %s, bucket',
            resource_type,
        )

    Resource = collections.namedtuple(
        'Resource',
        # fields based on required fields from Resource in dao.py.
        ['full_name', 'type', 'name', 'parent_type_name', 'parent',
         'data'],
    )

    bucket2 = Resource(
        full_name='organization/433637338589/project/ruihuang-hc-banana/bucket/ruihuang-hc-banana-mercury-bucket/',
        type='bucket/ruihuang-hc-banana-mercury-bucket',
        parent_type_name='project/ruihuang-hc-banana',
        name='ruihuang-hc-banana-mercury-bucket',
        parent=None,
        data='{"defaultObjectAcl": [{"entity": "project-owners-236807116121", "etag": "CAQ=", "kind": "storage#objectAccessControl", "projectTeam": {"projectNumber": "236807116121", "team": "owners"}, "role": "OWNER"}, {"entity": "project-editors-236807116121", "etag": "CAQ=", "kind": "storage#objectAccessControl", "projectTeam": {"projectNumber": "236807116121", "team": "editors"}, "role": "OWNER"}, {"entity": "project-viewers-236807116121", "etag": "CAQ=", "kind": "storage#objectAccessControl", "projectTeam": {"projectNumber": "236807116121", "team": "viewers"}, "role": "READER"}], "etag": "CAQ=", "id": "ruihuang-hc-banana-mercury-bucket", "kind": "storage#bucket", "lifecycle": {"rule": [{"action": {"type": "Delete"}, "condition": {"age": 20, "numNewerVersions": 5}}, {"action": {"type": "Delete"}, "condition": {"age": 10, "numNewerVersions": 99}}]}, "location": "US-CENTRAL1", "logging": {"logBucket": "ruihuang-hc-audit-logs-ruihuang-hc-banana", "logObjectPrefix": "ruihuang-hc-banana-mercury-bucket"}, "metageneration": "4", "name": "ruihuang-hc-banana-mercury-bucket", "owner": {"entity": "project-owners-236807116121"}, "projectNumber": "236807116121", "selfLink": "https://www.googleapis.com/storage/v1/b/ruihuang-hc-banana-mercury-bucket", "storageClass": "REGIONAL", "timeCreated": "2018-09-13T18:48:34.898Z", "updated": "2018-09-19T13:57:41.344Z", "versioning": {"enabled": true}}',
    )

    resources.append(bucket2)

    return resources

class RetentionScannerTest(ForsetiTestCase):

    def tekst_a(self):
        a=mock.MagicMock()
        a.id.r
        #print(a.id())
        print("\nRetention 3")

    def tekst_c(self):
        print("\nRetention 2")

    def tekst_d(self):
        print("\nRetention 1")

    
    @mock.patch(
        'google.cloud.forseti.scanner.scanners.retention_scanner.'
        'retention_rules_engine',
        autospec=True)
    def setUp(self, _):
        self.scanner = retention_scanner.RetentionScanner(
            {}, {}, mock.MagicMock(), '', '', '')


    #"lifecycle": {"rule": [{"action": {"type": "Delete"}, "condition": {"age": 20, "numNewerVersions": 5}}, {"action": {"type": "Delete"}, "condition": {"age": 10, "numNewerVersions": 99}}]},
    def test_retrieve(self):
        """Tests _retrieve gets all bq acls and parent resources."""
        print "retrieve \n"
        mock_data_access = mock.MagicMock()
        mock_data_access.scanner_iter.side_effect = _mock_gcp_resource_iter
        mock_service_config = mock.MagicMock()
        mock_service_config.model_manager = mock.MagicMock()
        mock_service_config.model_manager.get.return_value = (
            mock.MagicMock(), mock_data_access)
        self.scanner.service_config = mock_service_config

        bq_acl_data = self.scanner._retrieve()

