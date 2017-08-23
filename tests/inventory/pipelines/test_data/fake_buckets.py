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

"""Fake buckets data."""

FAKE_BUCKETS_MAP = [{
    'project_number': 11111,
    'buckets': [{
            'kind': 'storage#bucket',
            'name': 'fakebucket1',
            'timeCreated': '2016-07-21T12:57:04.604Z',
            'updated': '2016-07-21T12:57:04.604Z',
            'projectNumber': '11111',
            'metageneration': '2',
            'location': 'EU',
            'etag': 'CAE=',
            'id': 'fakebucket1',
            'selfLink': 'https://www.googleapis.com/storage/v1/b/fakebucket1',
            'storageClass': 'STANDARD',
            'lifecycle': {}
    }]
}]

EXPECTED_LOADABLE_BUCKETS = [{
    'project_number': 11111,
    'bucket_id': 'fakebucket1',
    'bucket_name': 'fakebucket1',
    'bucket_kind': 'storage#bucket',
    'bucket_storage_class': 'STANDARD',
    'bucket_location': 'EU',
    'bucket_create_time': '2016-07-21 12:57:04',
    'bucket_update_time': '2016-07-21 12:57:04',
    'bucket_selflink': 'https://www.googleapis.com/storage/v1/b/fakebucket1',
    'bucket_lifecycle_raw': '{}',
    'raw_bucket': '{"updated": "2016-07-21T12:57:04.604Z", "timeCreated": "2016-07-21T12:57:04.604Z", "metageneration": "2", "id": "fakebucket1", "kind": "storage#bucket", "name": "fakebucket1", "projectNumber": "11111", "etag": "CAE=", "storageClass": "STANDARD", "lifecycle": {}, "selfLink": "https://www.googleapis.com/storage/v1/b/fakebucket1", "location": "EU"}'
    }
]

FAKE_BUCKET_ACL_MAP = [{
    'bucket_name': 'fakebucket1',
    'acl': [
        {
            'kind': 'storage#bucketAccessControl', 
            'bucket': 'fakebucket1', 
            'entity': 'project-owners-11111', 
            'etag': 'CAE=', 
            'role': 'OWNER', 
            'projectTeam': {
                'projectNumber': '11111', 
                'team': 'owners'
                }, 
            'id': 'fakebucket1/project-owners-11111', 
            'selfLink': 'https://www.googleapis.com/storage/v1/b/fakebucket1/acl/project-owners-11111'
        },
        {
            'kind': 'storage#bucketAccessControl', 
            'bucket': 'fakebucket1', 
            'entity': 'project-readers-11111', 
            'etag': 'CAE=', 
            'role': 'READER', 
            'projectTeam': {
                'projectNumber': '11111', 
                'team': 'readers'}, 
                'id': 'fakebucket1/project-readers-11111', 
                'selfLink': 'https://www.googleapis.com/storage/v1/b/fakebucket1/acl/project-readers-11111'
        }
    ]
}]

EXPECTED_LOADABLE_BUCKET_ACLS = [{
      'acl_id': 'fakebucket1/project-owners-11111',
      'bucket': 'fakebucket1',
      'bucket_acl_selflink': 'https://www.googleapis.com/storage/v1/b/fakebucket1/acl/project-owners-11111',
      'domain': None,
      'email': None,
      'entity': 'project-owners-11111',
      'entity_id': None,
      'kind': 'storage#bucketAccessControl',
      'project_team': '{"projectNumber": "11111", "team": "owners"}',
      'raw_bucket_acl': '{"kind": "storage#bucketAccessControl", "etag": "CAE=", "role": "OWNER", "projectTeam": {"projectNumber": "11111", "team": "owners"}, "bucket": "fakebucket1", "id": "fakebucket1/project-owners-11111", "selfLink": "https://www.googleapis.com/storage/v1/b/fakebucket1/acl/project-owners-11111", "entity": "project-owners-11111"}',
      'role': 'OWNER'
      },
      {
      'acl_id': 'fakebucket1/project-readers-11111',
      'bucket': 'fakebucket1',
      'bucket_acl_selflink': 'https://www.googleapis.com/storage/v1/b/fakebucket1/acl/project-readers-11111',
      'domain': None,
      'email': None,
      'entity': 'project-readers-11111',
      'entity_id': None,
      'kind': 'storage#bucketAccessControl',
      'project_team': '{"projectNumber": "11111", "team": "readers"}',
      'raw_bucket_acl': '{"kind": "storage#bucketAccessControl", "etag": "CAE=", "role": "READER", "projectTeam": {"projectNumber": "11111", "team": "readers"}, "bucket": "fakebucket1", "id": "fakebucket1/project-readers-11111", "selfLink": "https://www.googleapis.com/storage/v1/b/fakebucket1/acl/project-readers-11111", "entity": "project-readers-11111"}',
      'role': 'READER'
}]

FAKE_RAW_BUCKET_ROW = [
    {
        'bucket_id': 'bucket1',
        'raw_bucket': """{
            "acl": [
                {"id": "bucket1/project-readers-1",
                 "role": "READER",
                 "bucket": "bucket1",
                 "domain": "",
                 "email": "",
                 "entity": "",
                 "entityId": "",
                 "kind": "",
                 "projectTeam": []
                }
            ],
            "id": "bucket1"
        }"""
    }
]

EXPECTED_RAW_BUCKET_JSON = [
    {
        'bucket_name': 'bucket1',
        'acl': [
            {'id': 'bucket1/project-readers-1',
             'role': 'READER',
             'bucket': 'bucket1',
             'domain': '',
             'email': '',
             'entity': '',
             'entityId': '',
             'kind': '',
             'projectTeam': [],
            }
        ]
    }
]
