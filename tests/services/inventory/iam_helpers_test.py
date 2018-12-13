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
"""Unit Tests: IAM Helpers for Forseti Server Inventory."""
import parameterized
from tests import unittest_utils
from google.cloud.forseti.services.inventory.base import iam_helpers


def make_iam_policy(role, members):
    """Create sample IAM policy."""
    return {'bindings':[{'role': role, 'members': members}]}


BIGQUERY_TESTS = [
    ('dataViewer-projectViewer',
     make_iam_policy('roles/bigquery.dataViewer', ['projectViewer:project']),
     [{'role': 'READER', 'specialGroup': 'projectReaders'}]),

    ('dataViewer-projectEditor',
     make_iam_policy('roles/bigquery.dataViewer', ['projectEditor:project']),
     [{'role': 'READER', 'specialGroup': 'projectWriters'}]),

    ('dataViewer-projectOwner',
     make_iam_policy('roles/bigquery.dataViewer', ['projectOwner:project']),
     [{'role': 'READER', 'specialGroup': 'projectOwners'}]),

    ('dataViewer-allAuthenticatedUsers',
     make_iam_policy('roles/bigquery.dataViewer', ['allAuthenticatedUsers']),
     [{'role': 'READER', 'specialGroup': 'allAuthenticatedUsers'}]),

    ('dataViewer-User',
     make_iam_policy('roles/bigquery.dataViewer', ['user:test@forseti.test']),
     [{'role': 'READER', 'userByEmail': 'test@forseti.test'}]),

    ('dataViewer-Group',
     make_iam_policy('roles/bigquery.dataViewer',
                     ['group:my-group@forseti.test']),
     [{'role': 'READER', 'groupByEmail': 'my-group@forseti.test'}]),

    ('dataViewer-Domain',
     make_iam_policy('roles/bigquery.dataViewer',
                     ['domain:forseti.test']),
     [{'role': 'READER', 'domain': 'forseti.test'}]),

    ('dataEditor-projectEditor',
     make_iam_policy('roles/bigquery.dataEditor', ['projectEditor:project']),
     [{'role': 'WRITER', 'specialGroup': 'projectWriters'}]),

    ('dataOwner-projectOwner',
     make_iam_policy('roles/bigquery.dataOwner', ['projectOwner:project']),
     [{'role': 'OWNER', 'specialGroup': 'projectOwners'}]),
]

TEST_BUCKET = 'my-bucket'
TEST_PROJECT_ID = 'project'
TEST_PROJECT_NUMBER = '12345'

STORAGE_TESTS = [
    ('reader-projectViewer',
     make_iam_policy('roles/storage.legacyBucketReader',
                     ['projectViewer:project']),
     [{'bucket': 'my-bucket',
       'id': 'my-bucket/project-viewers-12345',
       'entity': 'project-viewers-12345',
       'projectTeam': {'projectNumber': '12345', 'team': 'viewers'},
       'role': 'READER'}]),

    ('reader-projectEditor',
     make_iam_policy('roles/storage.legacyBucketReader',
                     ['projectEditor:project']),
     [{'bucket': 'my-bucket',
       'id': 'my-bucket/project-editors-12345',
       'entity': 'project-editors-12345',
       'projectTeam': {'projectNumber': '12345', 'team': 'editors'},
       'role': 'READER'}]),

    ('reader-projectOwners',
     make_iam_policy('roles/storage.legacyBucketReader',
                     ['projectOwner:project']),
     [{'bucket': 'my-bucket',
       'id': 'my-bucket/project-owners-12345',
       'entity': 'project-owners-12345',
       'projectTeam': {'projectNumber': '12345', 'team': 'owners'},
       'role': 'READER'}]),

    ('reader-allAuthenticatedUsers',
     make_iam_policy('roles/storage.legacyBucketReader',
                     ['allAuthenticatedUsers']),
     [{'bucket': 'my-bucket',
       'id': 'my-bucket/allAuthenticatedUsers',
       'entity': 'allAuthenticatedUsers',
       'role': 'READER'}]),

    ('reader-allUsers',
     make_iam_policy('roles/storage.legacyBucketReader',
                     ['allUsers']),
     [{'bucket': 'my-bucket',
       'id': 'my-bucket/allUsers',
       'entity': 'allUsers',
       'role': 'READER'}]),

    ('reader-User',
     make_iam_policy('roles/storage.legacyBucketReader',
                     ['user:test@forseti.test']),
     [{'bucket': 'my-bucket',
       'id': 'my-bucket/user-test@forseti.test',
       'entity': 'user-test@forseti.test',
       'email': 'test@forseti.test',
       'role': 'READER'}]),

    ('reader-serviceAccount',
     make_iam_policy('roles/storage.legacyBucketReader',
                     [('serviceAccount:12345-compute'
                       '@developer.gserviceaccount.com')]),
     [{'bucket': 'my-bucket',
       'id': 'my-bucket/user-12345-compute@developer.gserviceaccount.com',
       'entity': 'user-12345-compute@developer.gserviceaccount.com',
       'email': '12345-compute@developer.gserviceaccount.com',
       'role': 'READER'}]),

    ('reader-Group',
     make_iam_policy('roles/storage.legacyBucketReader',
                     ['group:my-group@forseti.test']),
     [{'bucket': 'my-bucket',
       'id': 'my-bucket/group-my-group@forseti.test',
       'entity': 'group-my-group@forseti.test',
       'email': 'my-group@forseti.test',
       'role': 'READER'}]),

    ('reader-Domain',
     make_iam_policy('roles/storage.legacyBucketReader',
                     ['domain:forseti.test']),
     [{'bucket': 'my-bucket',
       'id': 'my-bucket/domain-forseti.test',
       'entity': 'domain-forseti.test',
       'role': 'READER'}]),

    ('reader-other-projectViewer',
     make_iam_policy('roles/storage.legacyBucketReader',
                     ['projectViewer:other-project']),
     [{'bucket': 'my-bucket',
       'id': 'my-bucket/project-viewers-other-project',
       'entity': 'project-viewers-other-project',
       'projectTeam': {'projectNumber': 'other-project', 'team': 'viewers'},
       'role': 'READER'}]),

    ('writer-projectEditor',
     make_iam_policy('roles/storage.legacyBucketWriter',
                     ['projectEditor:project']),
     [{'bucket': 'my-bucket',
       'id': 'my-bucket/project-editors-12345',
       'entity': 'project-editors-12345',
       'projectTeam': {'projectNumber': '12345', 'team': 'editors'},
       'role': 'WRITER'}]),

    ('owner-projectOwners',
     make_iam_policy('roles/storage.legacyBucketOwner',
                     ['projectOwner:project']),
     [{'bucket': 'my-bucket',
       'id': 'my-bucket/project-owners-12345',
       'entity': 'project-owners-12345',
       'projectTeam': {'projectNumber': '12345', 'team': 'owners'},
       'role': 'OWNER'}]),

    ('other-role-User',
     make_iam_policy('roles/Editor',
                     ['user:test@forseti.test']),
     []),

    ('reader-unknown-member',
     make_iam_policy('roles/storage.legacyBucketReader',
                     ['unknown:test']),
     []),

    ('owner-and-writer-projectOwners',
     {'bindings': [{'role': 'roles/storage.legacyBucketOwner',
                    'members': ['projectOwner:project']},
                   {'role': 'roles/storage.legacyBucketWriter',
                    'members': ['projectOwner:project']}]},
     [{'bucket': 'my-bucket',
       'id': 'my-bucket/project-owners-12345',
       'entity': 'project-owners-12345',
       'projectTeam': {'projectNumber': '12345', 'team': 'owners'},
       'role': 'OWNER'}]),

    ('owner-and-reader-projectOwners',
     {'bindings': [{'role': 'roles/storage.legacyBucketOwner',
                    'members': ['projectOwner:project']},
                   {'role': 'roles/storage.legacyBucketReader',
                    'members': ['projectOwner:project']}]},
     [{'bucket': 'my-bucket',
       'id': 'my-bucket/project-owners-12345',
       'entity': 'project-owners-12345',
       'projectTeam': {'projectNumber': '12345', 'team': 'owners'},
       'role': 'OWNER'}]),

    ('writer-and-reader-projectOwners',
     {'bindings': [{'role': 'roles/storage.legacyBucketWriter',
                    'members': ['projectOwner:project']},
                   {'role': 'roles/storage.legacyBucketReader',
                    'members': ['projectOwner:project']}]},
     [{'bucket': 'my-bucket',
       'id': 'my-bucket/project-owners-12345',
       'entity': 'project-owners-12345',
       'projectTeam': {'projectNumber': '12345', 'team': 'owners'},
       'role': 'WRITER'}]),

    ('reader-writer-and-owner-projectOwners',
     {'bindings': [{'role': 'roles/storage.legacyBucketReader',
                    'members': ['projectOwner:project']},
                   {'role': 'roles/storage.legacyBucketWriter',
                    'members': ['projectOwner:project']},
                   {'role': 'roles/storage.legacyBucketOwner',
                    'members': ['projectOwner:project']}]},
     [{'bucket': 'my-bucket',
       'id': 'my-bucket/project-owners-12345',
       'entity': 'project-owners-12345',
       'projectTeam': {'projectNumber': '12345', 'team': 'owners'},
       'role': 'OWNER'}]),
]


class IamHelpersTest(unittest_utils.ForsetiTestCase):
    """Test iam helpers."""

    @parameterized.parameterized.expand(BIGQUERY_TESTS)
    def test_convert_iam_to_bigquery_policy(self, name, iam_policy,
                                            expected_result):
        """Validate IAM to Bigquery policy conversion."""
        result = iam_helpers.convert_iam_to_bigquery_policy(iam_policy)
        self.assertEqual(result, expected_result)

    @parameterized.parameterized.expand(STORAGE_TESTS)
    def test_convert_iam_to_bucket_acls(self, name, iam_policy,
                                        expected_result):
        """Validate IAM to Bucket Access Control policy conversion."""
        result = iam_helpers.convert_iam_to_bucket_acls(iam_policy,
                                                        TEST_BUCKET,
                                                        TEST_PROJECT_ID,
                                                        TEST_PROJECT_NUMBER)
        self.assertEqual(result, expected_result)

