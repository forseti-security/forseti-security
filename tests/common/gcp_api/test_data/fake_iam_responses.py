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

"""Test data for IAM GCP api responses."""

FAKE_PROJECT_ID = "forseti-system-test"
FAKE_SERVICEACCOUNT_NAME = (
    "projects/forseti-system-test/serviceAccounts/...")

GET_PROJECTS_SERVICEACCOUNTS = """
{
 "accounts": [
  {
   "name": "projects/forseti-system-test/serviceAccounts/111111-compute@developer.gserviceaccount.com",
   "projectId": "forseti-system-test",
   "uniqueId": "1234567890",
   "email": "111111-compute@developer.gserviceaccount.com",
   "displayName": "Compute Engine default service account",
   "etag": "etag",
   "oauth2ClientId": "1234567890"
  }
 ]
}
"""

EXPECTED_SERVICE_ACCOUNTS = [{
    "name": ("projects/forseti-system-test/serviceAccounts/"
             "111111-compute@developer.gserviceaccount.com"),
    "projectId": "forseti-system-test",
    "uniqueId": "1234567890",
    "email": "111111-compute@developer.gserviceaccount.com",
    "displayName": "Compute Engine default service account",
    "etag": "etag",
    "oauth2ClientId": "1234567890"}]

GET_PROJECTS_SERVICEACCOUNTS_KEYS = """
{
 "keys": [
  {
   "name": "projects/forseti-system-test/serviceAccounts/111111-compute@developer.gserviceaccount.com/keys/1234567890abcdef",
   "validAfterTime": "2017-08-21T07:55:36Z",
   "validBeforeTime": "2017-08-22T19:55:36Z",
   "keyAlgorithm": "KEY_ALG_RSA_2048"
  },
  {
   "name": "projects/forseti-system-test/serviceAccounts/111111-compute@developer.gserviceaccount.com/keys/1234567890abcdef",
   "validAfterTime": "2017-08-20T07:55:36Z",
   "validBeforeTime": "2017-08-21T19:55:36Z",
   "keyAlgorithm": "KEY_ALG_RSA_2048"
  }
 ]
}
"""

EXPECTED_SERVICE_ACCOUNT_KEYS = [
    {
        "name": ("projects/forseti-system-test/serviceAccounts/"
                 "111111-compute@developer.gserviceaccount.com/keys/"
                 "1234567890abcdef"),
        "validAfterTime": "2017-08-21T07:55:36Z",
        "validBeforeTime": "2017-08-22T19:55:36Z",
        "keyAlgorithm": "KEY_ALG_RSA_2048"
    }, {
        "name": ("projects/forseti-system-test/serviceAccounts/"
                 "111111-compute@developer.gserviceaccount.com/keys/"
                 "1234567890abcdef"),
        "validAfterTime": "2017-08-20T07:55:36Z",
        "validBeforeTime": "2017-08-21T19:55:36Z",
        "keyAlgorithm": "KEY_ALG_RSA_2048"
    }]

GET_PROJECT_SERVICEACCOUNT_IAM_POLICY = """
{
 "etag": "etag",
 "bindings": [
  {
   "role": "roles/owner",
   "members": [
    "user:testuser@foo.testing"
   ]
  }
 ]
}
"""

SERVICE_ACCOUNT_NOT_FOUND = """
{
 "error": {
  "code": 404,
  "message": "Service account projects/forseti-system-test/serviceAccounts/111111-compute@developer.gserviceaccount.com does not exist.",
  "status": "NOT_FOUND"
 }
}
"""

PERMISSION_DENIED = """
{
 "error": {
  "code": 403,
  "message": "The caller does not have permission",
  "status": "PERMISSION_DENIED"
 }
}
"""
