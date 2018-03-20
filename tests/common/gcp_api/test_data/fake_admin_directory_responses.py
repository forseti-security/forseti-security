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

"""Test data for GSuite Admin Directory GCP api responses."""

FAKE_GROUP_NAMES = ["aaaaa", "bbbbb", "CCCCC Users"]

FAKE_GROUPS_LIST_RESPONSE = """
{
 "kind": "admin#directory#groups",
 "etag": "etag",
 "groups": [{
    "nonEditableAliases": ["aaaaa@foo.com"],
    "kind": "admin#directory#group",
    "name": "aaaaa",
    "adminCreated": true,
    "directMembersCount": "1",
    "email": "aaaaa@foo.com",
    "etag": "pCd5iosDe_tWdPv4ke8sAYzlGK8/oWZC62Ysx9kAKLlW23uoKQlYu3k",
    "id": "11111",
    "description": ""
  },{
    "nonEditableAliases": ["bbbbb@foo.com"],
    "kind": "admin#directory#group",
    "name": "bbbbb",
    "adminCreated": false,
    "directMembersCount": "1",
    "email": "bbbbb@foo.com",
    "etag": "pCd5iosDe_tWdPv4ke8sAYzlGK8/cglP2U9YgiKA9zjJ-DvxjotnaLU",
    "id": "22222",
    "description": ""
  },{
    "nonEditableAliases": ["ccccc@foo.com"],
    "kind": "admin#directory#group",
    "name": "CCCCC Users",
    "adminCreated": true,
    "directMembersCount": "4",
    "email": "ccccc@foo.com",
    "etag": "pCd5iosDe_tWdPv4ke8sAYzlGK8/kQ2NdfLnWQTiAs-FCSEKJRaipxw",
    "id": "33333",
    "description": "Members of this group will be allowed to perform bar."
  }
 ]
}
"""

FAKE_MEMBERS_LIST_RESPONSE1 = """
{
 "kind": "admin#directory#members",
 "etag": "etag",
 "members": [{
    "kind": "admin#directory#member",
    "etag": "abcd1234ABCD1234",
    "id": "11111",
    "email": "writer@my-gcp-project.iam.gserviceaccount.com",
    "role": "MEMBER",
    "type": "USER",
    "status": "ACTIVE"
  },{
    "kind": "admin#directory#member",
    "etag": "efgh1234EFGH1234",
    "id": "22222",
    "email": "myuser@mydomain.com",
    "role": "MEMBER",
    "type": "USER",
    "status": "ACTIVE"
  },{
    "kind": "admin#directory#member",
    "etag": "hijk1234HIJK1234",
    "id": "33333",
    "role": "MEMBER",
    "type": "USER",
    "status": "ACTIVE"
  }
 ]
}
"""

FAKE_MEMBERS_LIST_RESPONSE2 = """
{
 "kind": "admin#directory#members",
 "etag": "etag",
 "members": [{
    "kind": "admin#directory#member",
    "etag": "abcd1234ABCD1234",
    "id": "44444",
    "email": "reader@my-gcp-project.iam.gserviceaccount.com",
    "role": "MEMBER",
    "type": "USER",
    "status": "ACTIVE"
  },{
    "kind": "admin#directory#member",
    "etag": "efgh1234EFGH1234",
    "id": "55555",
    "email": "myuser2@mydomain.com",
    "role": "OWNER",
    "type": "USER",
    "status": "ACTIVE"
  }
 ]
}
"""

FAKE_USERS_LIST_RESPONSE = """
{
 "kind": "admin#directory#users",
 "etag": "etag",
 "users": [{
  "kind": "admin#directory#user",
  "id": "12345",
  "etag": "a",
  "primaryEmail": "auser@mydomain.test",
  "name": {
   "givenName": "A",
   "familyName": "User",
   "fullName": "A User"
  },
  "emails": [
   {
    "address": "auser@mydomain.test",
    "primary": true
   }
  ]
 }]
}
"""

UNAUTHORIZED = """
{
 "error": {
  "errors": [
   {
    "domain": "global",
    "reason": "forbidden",
    "message": "Not Authorized to access this resource/api"
   }
  ],
  "code": 403,
  "message": "Not Authorized to access this resource/api"
 }
}
"""
