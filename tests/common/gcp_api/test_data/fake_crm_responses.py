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

"""Test data for Cloud Resource Manager GCP api responses."""

FAKE_PROJECT_NUMBER = "1111111"
FAKE_PROJECT_ID = "forseti-system-test"
FAKE_ORG_ID = "2222222"
FAKE_FOLDER_ID = "3333333"

GET_PROJECT_RESPONSE = """
{
 "projectNumber": "1111111",
 "projectId": "forseti-system-test",
 "lifecycleState": "ACTIVE",
 "name": "Forseti Security Tests",
 "createTime": "2017-07-12T17:50:40.895Z",
 "parent": {
  "type": "organization",
  "id": "2222222"
 }
}
"""

GET_PROJECT_NOT_FOUND = """
{
 "error": {
  "code": 403,
  "message": "The caller does not have permission",
  "status": "PERMISSION_DENIED"
 }
}
"""

GET_IAM_POLICY = """
{
 "version": 1,
 "etag": "BwVVEmTu/ww=",
 "bindings": [
  {
   "role": "roles/editor",
   "members": [
    "serviceAccount:1111111-compute@developer.gserviceaccount.com",
    "serviceAccount:1111111@cloudservices.gserviceaccount.com"
   ]
  },
  {
   "role": "roles/owner",
   "members": [
    "group:test@forsetisecurity.testing",
    "user:testuser@forsetisecurity.testing"
   ]
  }
 ]
}
"""

GET_ORGANIZATION = """
{
 "displayName": "forsetisecurity.testing",
 "owner": {
  "directoryCustomerId": "ABC123DEF"
 },
 "creationTime": "2015-09-09T19:34:18.591Z",
 "lifecycleState": "ACTIVE",
 "name": "organizations/2222222"
}
"""

GET_FOLDER = """
{
 "name": "folders/3333333",
 "parent": "organizations/2222222",
 "displayName": "folder-forseti-test",
 "lifecycleState": "ACTIVE",
 "createTime": "2017-02-09T22:02:07.769Z"
}
"""
