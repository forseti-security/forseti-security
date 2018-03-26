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

"""Test data for Storage GCP api responses."""

FAKE_PROJECT_NUMBER = "1111111"

GET_BUCKETS_RESPONSE_PAGE1 = """
{
 "kind": "storage#buckets",
 "items": [
  {
   "kind": "storage#bucket",
   "id": "forseti-system-test.a.testing",
   "selfLink": "https://www.googleapis.com/storage/v1/b/forseti-system-test.a.testing",
   "projectNumber": "1111111",
   "name": "forseti-system-test.a.testing",
   "timeCreated": "2017-01-18T18:57:23.536Z",
   "updated": "2017-01-18T18:57:23.536Z",
   "metageneration": "1",
   "acl": [
    {
     "kind": "storage#bucketAccessControl",
     "id": "forseti-system-test.a.testing/project-owners-1111111",
     "selfLink": "https://www.googleapis.com/storage/v1/b/forseti-system-test.a.testing/acl/project-owners-1111111",
     "bucket": "forseti-system-test.a.testing",
     "entity": "project-owners-1111111",
     "role": "OWNER",
     "projectTeam": {
      "projectNumber": "1111111",
      "team": "owners"
     },
     "etag": "CAE="
    },
    {
     "kind": "storage#bucketAccessControl",
     "id": "forseti-system-test.a.testing/project-editors-1111111",
     "selfLink": "https://www.googleapis.com/storage/v1/b/forseti-system-test.a.testing/acl/project-editors-1111111",
     "bucket": "forseti-system-test.a.testing",
     "entity": "project-editors-1111111",
     "role": "OWNER",
     "projectTeam": {
      "projectNumber": "1111111",
      "team": "editors"
     },
     "etag": "CAE="
    },
    {
     "kind": "storage#bucketAccessControl",
     "id": "forseti-system-test.a.testing/project-viewers-1111111",
     "selfLink": "https://www.googleapis.com/storage/v1/b/forseti-system-test.a.testing/acl/project-viewers-1111111",
     "bucket": "forseti-system-test.a.testing",
     "entity": "project-viewers-1111111",
     "role": "READER",
     "projectTeam": {
      "projectNumber": "1111111",
      "team": "viewers"
     },
     "etag": "CAE="
    }
   ],
   "defaultObjectAcl": [
    {
     "kind": "storage#objectAccessControl",
     "entity": "project-owners-1111111",
     "role": "OWNER",
     "projectTeam": {
      "projectNumber": "1111111",
      "team": "owners"
     },
     "etag": "CAE="
    },
    {
     "kind": "storage#objectAccessControl",
     "entity": "project-editors-1111111",
     "role": "OWNER",
     "projectTeam": {
      "projectNumber": "1111111",
      "team": "editors"
     },
     "etag": "CAE="
    },
    {
     "kind": "storage#objectAccessControl",
     "entity": "project-viewers-1111111",
     "role": "READER",
     "projectTeam": {
      "projectNumber": "1111111",
      "team": "viewers"
     },
     "etag": "CAE="
    }
   ],
   "owner": {
    "entity": "project-owners-1111111"
   },
   "location": "US",
   "storageClass": "STANDARD",
   "etag": "CAE="
  }
 ],
 "nextPageToken": "123"
}
"""

GET_BUCKETS_RESPONSE_PAGE2 = """
{
 "kind": "storage#buckets",
 "items": [
  {
   "kind": "storage#bucket",
   "id": "staging.forseti-system-test.a.testing",
   "selfLink": "https://www.googleapis.com/storage/v1/b/staging.forseti-system-test.a.testing",
   "projectNumber": "1111111",
   "name": "staging.forseti-system-test.a.testing",
   "timeCreated": "2017-01-18T18:57:23.515Z",
   "updated": "2017-01-18T18:57:23.515Z",
   "metageneration": "1",
   "acl": [
    {
     "kind": "storage#bucketAccessControl",
     "id": "staging.forseti-system-test.a.testing/project-owners-1111111",
     "selfLink": "https://www.googleapis.com/storage/v1/b/staging.forseti-system-test.a.testing/acl/project-owners-1111111",
     "bucket": "staging.forseti-system-test.a.testing",
     "entity": "project-owners-1111111",
     "role": "OWNER",
     "projectTeam": {
      "projectNumber": "1111111",
      "team": "owners"
     },
     "etag": "CAE="
    },
    {
     "kind": "storage#bucketAccessControl",
     "id": "staging.forseti-system-test.a.testing/project-editors-1111111",
     "selfLink": "https://www.googleapis.com/storage/v1/b/staging.forseti-system-test.a.testing/acl/project-editors-1111111",
     "bucket": "staging.forseti-system-test.a.testing",
     "entity": "project-editors-1111111",
     "role": "OWNER",
     "projectTeam": {
      "projectNumber": "1111111",
      "team": "editors"
     },
     "etag": "CAE="
    },
    {
     "kind": "storage#bucketAccessControl",
     "id": "staging.forseti-system-test.a.testing/project-viewers-1111111",
     "selfLink": "https://www.googleapis.com/storage/v1/b/staging.forseti-system-test.a.testing/acl/project-viewers-1111111",
     "bucket": "staging.forseti-system-test.a.testing",
     "entity": "project-viewers-1111111",
     "role": "READER",
     "projectTeam": {
      "projectNumber": "1111111",
      "team": "viewers"
     },
     "etag": "CAE="
    }
   ],
   "defaultObjectAcl": [
    {
     "kind": "storage#objectAccessControl",
     "entity": "project-owners-1111111",
     "role": "OWNER",
     "projectTeam": {
      "projectNumber": "1111111",
      "team": "owners"
     },
     "etag": "CAE="
    },
    {
     "kind": "storage#objectAccessControl",
     "entity": "project-editors-1111111",
     "role": "OWNER",
     "projectTeam": {
      "projectNumber": "1111111",
      "team": "editors"
     },
     "etag": "CAE="
    },
    {
     "kind": "storage#objectAccessControl",
     "entity": "project-viewers-1111111",
     "role": "READER",
     "projectTeam": {
      "projectNumber": "1111111",
      "team": "viewers"
     },
     "etag": "CAE="
    }
   ],
   "owner": {
    "entity": "project-owners-1111111"
   },
   "location": "US",
   "lifecycle": {
    "rule": [
     {
      "action": {
       "type": "Delete"
      },
      "condition": {
       "age": 15
      }
     }
    ]
   },
   "storageClass": "STANDARD",
   "etag": "CAE="
  }
 ]
}
"""

GET_BUCKETS_RESPONSES = [GET_BUCKETS_RESPONSE_PAGE1,
                         GET_BUCKETS_RESPONSE_PAGE2]

EXPECTED_FAKE_BUCKET_NAMES = ["forseti-system-test.a.testing",
                              "staging.forseti-system-test.a.testing"]

FAKE_BUCKET_NAME = EXPECTED_FAKE_BUCKET_NAMES[0]
GET_BUCKET_IAM_POLICY_RESPONSE = """
{
 "kind": "storage#policy",
 "resourceId": "projects/_/buckets/forseti-system-test.a.testing",
 "bindings": [
  {
   "role": "roles/storage.legacyBucketOwner",
   "members": [
    "projectEditor:forseti-system-test",
    "projectOwner:forseti-system-test"
   ]
  },
  {
   "role": "roles/storage.legacyBucketReader",
   "members": [
    "projectViewer:forseti-system-test"
   ]
  }
 ],
 "etag": "CAE="
}
"""

GET_BUCKET_ACL = """
{
 "kind": "storage#bucketAccessControls",
 "items": [
  {
   "kind": "storage#bucketAccessControl",
   "id": "forseti-system-test.a.testing/project-owners-1111111",
   "selfLink": "https://www.googleapis.com/storage/v1/b/forseti-system-test.a.testing/acl/project-owners-1111111",
   "bucket": "forseti-system-test.a.testing",
   "entity": "project-owners-1111111",
   "role": "OWNER",
   "projectTeam": {
    "projectNumber": "1111111",
    "team": "owners"
   },
   "etag": "CAE="
  },
  {
   "kind": "storage#bucketAccessControl",
   "id": "forseti-system-test.a.testing/project-editors-1111111",
   "selfLink": "https://www.googleapis.com/storage/v1/b/forseti-system-test.a.testing/acl/project-editors-1111111",
   "bucket": "forseti-system-test.a.testing",
   "entity": "project-editors-1111111",
   "role": "OWNER",
   "projectTeam": {
    "projectNumber": "1111111",
    "team": "editors"
   },
   "etag": "CAE="
  },
  {
   "kind": "storage#bucketAccessControl",
   "id": "forseti-system-test.a.testing/project-viewers-1111111",
   "selfLink": "https://www.googleapis.com/storage/v1/b/forseti-system-test.a.testing/acl/project-viewers-1111111",
   "bucket": "forseti-system-test.a.testing",
   "entity": "project-viewers-1111111",
   "role": "READER",
   "projectTeam": {
    "projectNumber": "1111111",
    "team": "viewers"
   },
   "etag": "CAE="
  }
 ]
}
"""

DEFAULT_OBJECT_ACL = """
{
 "kind": "storage#objectAccessControls",
 "items": [
  {
   "kind": "storage#objectAccessControl",
   "entity": "project-owners-1111111",
   "role": "OWNER",
   "projectTeam": {
    "projectNumber": "1111111",
    "team": "owners"
   },
   "etag": "CAE="
  },
  {
   "kind": "storage#objectAccessControl",
   "entity": "project-editors-1111111",
   "role": "OWNER",
   "projectTeam": {
    "projectNumber": "1111111",
    "team": "editors"
   },
   "etag": "CAE="
  },
  {
   "kind": "storage#objectAccessControl",
   "entity": "project-viewers-1111111",
   "role": "READER",
   "projectTeam": {
    "projectNumber": "1111111",
    "team": "viewers"
   },
   "etag": "CAE="
  }
 ]
}
"""

LIST_OBJECTS_RESPONSE_PAGE1 = """
{
 "kind": "storage#objects",
 "nextPageToken": "123",
 "items": [
  {
   "kind": "storage#object",
   "id": "us.artifacts.forseti-system-test.a.testing/containers/images/sha256:fedcba0987654321/1486055356404000",
   "selfLink": "https://www.googleapis.com/storage/v1/b/us.artifacts.forseti-system-test.a.testing/o/containers%2Fimages%2Fsha256:fedcba0987654321",
   "name": "containers/images/sha256:fedcba0987654321",
   "bucket": "us.artifacts.forseti-system-test.a.testing",
   "generation": "1486055356404000",
   "metageneration": "1",
   "contentType": "application/octet-stream",
   "timeCreated": "2017-02-02T17:09:16.393Z",
   "updated": "2017-02-02T17:09:16.393Z",
   "storageClass": "STANDARD",
   "timeStorageClassUpdated": "2017-02-02T17:09:16.393Z",
   "size": "6558",
   "md5Hash": "LL2O/JJ1pmrSXnv5zcku5g==",
   "mediaLink": "https://www.googleapis.com/download/storage/v1/b/us.artifacts.forseti-system-test.a.testing/o/containers%2Fimages%2Fsha256:fedcba0987654321?generation=1486055356404000&alt=media",
   "acl": [
    {
     "kind": "storage#objectAccessControl",
     "id": "us.artifacts.forseti-system-test.a.testing/containers/images/sha256:fedcba0987654321/1486055356404000/project-owners-1111111",
     "selfLink": "https://www.googleapis.com/storage/v1/b/us.artifacts.forseti-system-test.a.testing/o/containers%2Fimages%2Fsha256:fedcba0987654321/acl/project-owners-1111111",
     "bucket": "us.artifacts.forseti-system-test.a.testing",
     "object": "containers/images/sha256:fedcba0987654321",
     "generation": "1486055356404000",
     "entity": "project-owners-1111111",
     "role": "OWNER",
     "projectTeam": {
      "projectNumber": "1111111",
      "team": "owners"
     },
     "etag": "CKCiis3z8dECEAE="
    },
    {
     "kind": "storage#objectAccessControl",
     "id": "us.artifacts.forseti-system-test.a.testing/containers/images/sha256:fedcba0987654321/1486055356404000/project-editors-1111111",
     "selfLink": "https://www.googleapis.com/storage/v1/b/us.artifacts.forseti-system-test.a.testing/o/containers%2Fimages%2Fsha256:fedcba0987654321/acl/project-editors-1111111",
     "bucket": "us.artifacts.forseti-system-test.a.testing",
     "object": "containers/images/sha256:fedcba0987654321",
     "generation": "1486055356404000",
     "entity": "project-editors-1111111",
     "role": "OWNER",
     "projectTeam": {
      "projectNumber": "1111111",
      "team": "editors"
     },
     "etag": "CKCiis3z8dECEAE="
    },
    {
     "kind": "storage#objectAccessControl",
     "id": "us.artifacts.forseti-system-test.a.testing/containers/images/sha256:fedcba0987654321/1486055356404000/project-viewers-1111111",
     "selfLink": "https://www.googleapis.com/storage/v1/b/us.artifacts.forseti-system-test.a.testing/o/containers%2Fimages%2Fsha256:fedcba0987654321/acl/project-viewers-1111111",
     "bucket": "us.artifacts.forseti-system-test.a.testing",
     "object": "containers/images/sha256:fedcba0987654321",
     "generation": "1486055356404000",
     "entity": "project-viewers-1111111",
     "role": "READER",
     "projectTeam": {
      "projectNumber": "1111111",
      "team": "viewers"
     },
     "etag": "CKCiis3z8dECEAE="
    },
    {
     "kind": "storage#objectAccessControl",
     "id": "us.artifacts.forseti-system-test.a.testing/containers/images/sha256:fedcba0987654321/1486055356404000/user-1111111@cloudbuild.gserviceaccount.com",
     "selfLink": "https://www.googleapis.com/storage/v1/b/us.artifacts.forseti-system-test.a.testing/o/containers%2Fimages%2Fsha256:fedcba0987654321/acl/user-1111111@cloudbuild.gserviceaccount.com",
     "bucket": "us.artifacts.forseti-system-test.a.testing",
     "object": "containers/images/sha256:fedcba0987654321",
     "generation": "1486055356404000",
     "entity": "user-1111111@cloudbuild.gserviceaccount.com",
     "role": "OWNER",
     "email": "1111111@cloudbuild.gserviceaccount.com",
     "etag": "CKCiis3z8dECEAE="
    }
   ],
   "owner": {
    "entity": "user-1111111@cloudbuild.gserviceaccount.com"
   },
   "crc32c": "AGgzEg==",
   "etag": "CKCiis3z8dECEAE="
  }
 ]
}
"""

LIST_OBJECTS_RESPONSE_PAGE2 = """
{
 "kind": "storage#objects",
 "items": [
  {
   "kind": "storage#object",
   "id": "us.artifacts.forseti-system-test.a.testing/containers/images/sha256:1234567890abcdef/1484765930974000",
   "selfLink": "https://www.googleapis.com/storage/v1/b/us.artifacts.forseti-system-test.a.testing/o/containers%2Fimages%2Fsha256:1234567890abcdef",
   "name": "containers/images/sha256:1234567890abcdef",
   "bucket": "us.artifacts.forseti-system-test.a.testing",
   "generation": "1484765930974000",
   "metageneration": "1",
   "contentType": "application/octet-stream",
   "timeCreated": "2017-01-18T18:58:50.959Z",
   "updated": "2017-01-18T18:58:50.959Z",
   "storageClass": "STANDARD",
   "timeStorageClassUpdated": "2017-01-18T18:58:50.959Z",
   "size": "50546722",
   "md5Hash": "nyqU+nhvyRb9xxvaKMFfLA==",
   "mediaLink": "https://www.googleapis.com/download/storage/v1/b/us.artifacts.forseti-system-test.a.testing/o/containers%2Fimages%2Fsha256:1234567890abcdef?generation=1484765930974000&alt=media",
   "acl": [
    {
     "kind": "storage#objectAccessControl",
     "id": "us.artifacts.forseti-system-test.a.testing/containers/images/sha256:1234567890abcdef/1484765930974000/project-owners-1111111",
     "selfLink": "https://www.googleapis.com/storage/v1/b/us.artifacts.forseti-system-test.a.testing/o/containers%2Fimages%2Fsha256:1234567890abcdef/acl/project-owners-1111111",
     "bucket": "us.artifacts.forseti-system-test.a.testing",
     "object": "containers/images/sha256:1234567890abcdef",
     "generation": "1484765930974000",
     "entity": "project-owners-1111111",
     "role": "OWNER",
     "projectTeam": {
      "projectNumber": "1111111",
      "team": "owners"
     },
     "etag": "CLDWj4+wzNECEAE="
    },
    {
     "kind": "storage#objectAccessControl",
     "id": "us.artifacts.forseti-system-test.a.testing/containers/images/sha256:1234567890abcdef/1484765930974000/project-editors-1111111",
     "selfLink": "https://www.googleapis.com/storage/v1/b/us.artifacts.forseti-system-test.a.testing/o/containers%2Fimages%2Fsha256:1234567890abcdef/acl/project-editors-1111111",
     "bucket": "us.artifacts.forseti-system-test.a.testing",
     "object": "containers/images/sha256:1234567890abcdef",
     "generation": "1484765930974000",
     "entity": "project-editors-1111111",
     "role": "OWNER",
     "projectTeam": {
      "projectNumber": "1111111",
      "team": "editors"
     },
     "etag": "CLDWj4+wzNECEAE="
    },
    {
     "kind": "storage#objectAccessControl",
     "id": "us.artifacts.forseti-system-test.a.testing/containers/images/sha256:1234567890abcdef/1484765930974000/project-viewers-1111111",
     "selfLink": "https://www.googleapis.com/storage/v1/b/us.artifacts.forseti-system-test.a.testing/o/containers%2Fimages%2Fsha256:1234567890abcdef/acl/project-viewers-1111111",
     "bucket": "us.artifacts.forseti-system-test.a.testing",
     "object": "containers/images/sha256:1234567890abcdef",
     "generation": "1484765930974000",
     "entity": "project-viewers-1111111",
     "role": "READER",
     "projectTeam": {
      "projectNumber": "1111111",
      "team": "viewers"
     },
     "etag": "CLDWj4+wzNECEAE="
    },
    {
     "kind": "storage#objectAccessControl",
     "id": "us.artifacts.forseti-system-test.a.testing/containers/images/sha256:1234567890abcdef/1484765930974000/user-1111111@cloudbuild.gserviceaccount.com",
     "selfLink": "https://www.googleapis.com/storage/v1/b/us.artifacts.forseti-system-test.a.testing/o/containers%2Fimages%2Fsha256:1234567890abcdef/acl/user-1111111@cloudbuild.gserviceaccount.com",
     "bucket": "us.artifacts.forseti-system-test.a.testing",
     "object": "containers/images/sha256:1234567890abcdef",
     "generation": "1484765930974000",
     "entity": "user-1111111@cloudbuild.gserviceaccount.com",
     "role": "OWNER",
     "email": "1111111@cloudbuild.gserviceaccount.com",
     "etag": "CLDWj4+wzNECEAE="
    }
   ],
   "owner": {
    "entity": "user-1111111@cloudbuild.gserviceaccount.com"
   },
   "crc32c": "BnfuCw==",
   "etag": "CLDWj4+wzNECEAE="
  }
 ]
}
"""

LIST_OBJECTS_RESPONSES = [LIST_OBJECTS_RESPONSE_PAGE1,
                          LIST_OBJECTS_RESPONSE_PAGE2]

EXPECTED_FAKE_OBJECT_NAMES = ["containers/images/sha256:fedcba0987654321",
                              "containers/images/sha256:1234567890abcdef"]

FAKE_OBJECT_NAME = EXPECTED_FAKE_OBJECT_NAMES[0]
GET_OBJECT_IAM_POLICY_RESPONSE = """
{
 "kind": "storage#policy",
 "resourceId": "projects/_/buckets/forseti-system-test.a.testing/objects/containers/images/sha256:fedcba0987654321#0",
 "bindings": [
  {
   "role": "roles/storage.legacyObjectOwner",
   "members": [
    "projectOwner:forseti-system-test",
    "projectEditor:forseti-system-test",
    "serviceAccount:111111@cloudbuild.gserviceaccount.com"
   ]
  },
  {
   "role": "roles/storage.legacyObjectReader",
   "members": [
    "projectViewer:forseti-system-test"
   ]
  }
 ],
 "etag": "CAE="
}
"""

GET_OBJECT_ACL = """
{
 "kind": "storage#objectAccessControls",
 "items": [
  {
   "kind": "storage#objectAccessControl",
   "id": "us.artifacts.forseti-system-test.a.testing/containers/images/sha256:fedcba0987654321/1486055356404000/project-owners-1111111",
   "selfLink": "https://www.googleapis.com/storage/v1/b/us.artifacts.forseti-system-test.a.testing/o/containers%2Fimages%2Fsha256:fedcba0987654321/acl/project-owners-1111111",
   "bucket": "us.artifacts.forseti-system-test.a.testing",
   "object": "containers/images/sha256:fedcba0987654321",
   "generation": "1486055356404000",
   "entity": "project-owners-1111111",
   "role": "OWNER",
   "projectTeam": {
    "projectNumber": "1111111",
    "team": "owners"
   },
   "etag": "CKCiis3z8dECEAE="
  },
  {
   "kind": "storage#objectAccessControl",
   "id": "us.artifacts.forseti-system-test.a.testing/containers/images/sha256:fedcba0987654321/1486055356404000/project-editors-1111111",
   "selfLink": "https://www.googleapis.com/storage/v1/b/us.artifacts.forseti-system-test.a.testing/o/containers%2Fimages%2Fsha256:fedcba0987654321/acl/project-editors-1111111",
   "bucket": "us.artifacts.forseti-system-test.a.testing",
   "object": "containers/images/sha256:fedcba0987654321",
   "generation": "1486055356404000",
   "entity": "project-editors-1111111",
   "role": "OWNER",
   "projectTeam": {
    "projectNumber": "1111111",
    "team": "editors"
   },
   "etag": "CKCiis3z8dECEAE="
  },
  {
   "kind": "storage#objectAccessControl",
   "id": "us.artifacts.forseti-system-test.a.testing/containers/images/sha256:fedcba0987654321/1486055356404000/project-viewers-1111111",
   "selfLink": "https://www.googleapis.com/storage/v1/b/us.artifacts.forseti-system-test.a.testing/o/containers%2Fimages%2Fsha256:fedcba0987654321/acl/project-viewers-1111111",
   "bucket": "us.artifacts.forseti-system-test.a.testing",
   "object": "containers/images/sha256:fedcba0987654321",
   "generation": "1486055356404000",
   "entity": "project-viewers-1111111",
   "role": "READER",
   "projectTeam": {
    "projectNumber": "1111111",
    "team": "viewers"
   },
   "etag": "CKCiis3z8dECEAE="
  },
  {
   "kind": "storage#objectAccessControl",
   "id": "us.artifacts.forseti-system-test.a.testing/containers/images/sha256:fedcba0987654321/1486055356404000/user-1111111@cloudbuild.gserviceaccount.com",
   "selfLink": "https://www.googleapis.com/storage/v1/b/us.artifacts.forseti-system-test.a.testing/o/containers%2Fimages%2Fsha256:fedcba0987654321/acl/user-1111111@cloudbuild.gserviceaccount.com",
   "bucket": "us.artifacts.forseti-system-test.a.testing",
   "object": "containers/images/sha256:fedcba0987654321",
   "generation": "1486055356404000",
   "entity": "user-1111111@cloudbuild.gserviceaccount.com",
   "role": "OWNER",
   "email": "1111111@cloudbuild.gserviceaccount.com",
   "etag": "CKCiis3z8dECEAE="
  }
 ]
}
"""

# Errors

ACCESS_FORBIDDEN = """
{
 "error": {
  "errors": [
   {
    "domain": "global",
    "reason": "forbidden",
    "message": "user does not have storage.buckets.list access to project 1111111."
   }
  ],
  "code": 403,
  "message": "user does not have storage.buckets.list access to project 1111111."
 }
}
"""

NOT_FOUND = """
{
 "error": {
  "errors": [
   {
    "domain": "global",
    "reason": "notFound",
    "message": "Not Found"
   }
  ],
  "code": 404,
  "message": "Not Found"
 }
}
"""

USER_PROJECT_MISSING = """
{
 "error": {
  "errors": [
   {
    "domain": "global",
    "reason": "required",
    "message": "Bucket is requester pays bucket but no user project provided."
   }
  ],
  "code": 400,
  "message": "Bucket is requester pays bucket but no user project provided."
 }
}
"""
