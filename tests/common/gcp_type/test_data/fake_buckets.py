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

FAKE_BUCKETS_RESPONSE = {
	'items': [{
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
	      'storageClass': 'STANDARD'
	    },
	    {
	      'kind': 'storage#bucket',
	      'name': 'fakebucket2',
	      'timeCreated': '2016-08-21T12:57:04.604Z',
	      'updated': '2016-08-21T12:57:04.604Z',
	      'projectNumber': '11111',
	      'metageneration': '1',
	      'location': 'US',
	      'etag': 'CAE=',
	      'id': 'fakebucket2',
	      'selfLink': 'https://www.googleapis.com/storage/v1/b/fakebucket1',
	      'storageClass': 'STANDARD'
	    }
	]
}

EXPECTED_FAKE_BUCKETS_FROM_API = [FAKE_BUCKETS_RESPONSE]

FAKE_BUCKET_ACLS_RESPONSE = {
    'items': [{
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
          'entity': 'project-editors-11111', 
          'etag': 'CAE=', 
          'role': 'OWNER', 
          'projectTeam': {
                'projectNumber': '11111', 
                'team': 'editors'
                }, 
          'id': 'fakebucket1/project-editors-11111', 
          'selfLink': 'https://www.googleapis.com/storage/v1/b/fakebucket1/acl/project-editors-11111'
        }, 
        {
          'kind': 'storage#bucketAccessControl', 
          'bucket': 'fakebucket1', 
          'entity': 'project-viewers-111111', 
          'etag': 'CAE=', 
          'role': 'READER', 
          'projectTeam': {
                'projectNumber': '11111', 
                'team': 'viewers'}, 
           'id': 'afakebucket1/project-viewers-11111', 
           'selfLink': 'https://www.googleapis.com/storage/v1/b/fakebucket1/acl/project-viewers-11111'}
    ]
}

EXPECTED_FAKE_BUCKET_ACLS_FROM_API = [FAKE_BUCKET_ACLS_RESPONSE]
