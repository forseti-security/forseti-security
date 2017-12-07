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

"""Test data for IAM GCP api responses."""

FAKE_PROJECT_ID = "forseti-system-test"
FAKE_ORG_ID = "1234567890"
FAKE_SERVICEACCOUNT_NAME = (
    "projects/forseti-system-test/serviceAccounts/...")

GET_ROLES_PAGE_1 = """
{
 "roles": [
  {
   "name": "roles/appengine.appAdmin",
   "title": "App Engine Admin",
   "description": "Full management of App Engine apps (but not storage).",
   "includedPermissions": [
    "appengine.applications.disable",
    "appengine.applications.get",
    "appengine.applications.update",
    "appengine.instances.delete",
    "appengine.instances.get",
    "appengine.instances.list",
    "appengine.instances.update",
    "appengine.operations.cancel",
    "appengine.operations.delete",
    "appengine.operations.get",
    "appengine.operations.list",
    "appengine.runtimes.actAsAdmin",
    "appengine.services.delete",
    "appengine.services.get",
    "appengine.services.list",
    "appengine.services.update",
    "appengine.versions.create",
    "appengine.versions.delete",
    "appengine.versions.get",
    "appengine.versions.list",
    "appengine.versions.update",
    "resourcemanager.projects.get",
    "resourcemanager.projects.list"
   ],
   "stage": "GA",
   "etag": "AA=="
  }
 ],
 "nextPageToken": "1"
}
"""

GET_ROLES_PAGE_2 = """
{
 "roles": [
  {
   "name": "roles/appengine.appViewer",
   "title": "App Engine Viewer",
   "description": "Ability to view App Engine app status.",
   "includedPermissions": [
    "appengine.applications.get",
    "appengine.instances.get",
    "appengine.instances.list",
    "appengine.operations.get",
    "appengine.operations.list",
    "appengine.services.get",
    "appengine.services.list",
    "appengine.versions.get",
    "appengine.versions.list",
    "resourcemanager.projects.get",
    "resourcemanager.projects.list"
   ],
   "stage": "GA",
   "etag": "AA=="
  }
 ],
 "nextPageToken": "2"
}
"""

GET_ROLES_PAGE_3 = """
{
 "roles": [
  {
   "name": "roles/appengine.codeViewer",
   "title": "App Engine Code Viewer",
   "description": "Ability to view App Engine app status and deployed source code.",
   "includedPermissions": [
    "appengine.applications.get",
    "appengine.instances.get",
    "appengine.instances.list",
    "appengine.operations.get",
    "appengine.operations.list",
    "appengine.services.get",
    "appengine.services.list",
    "appengine.versions.get",
    "appengine.versions.getFileContents",
    "appengine.versions.list",
    "resourcemanager.projects.get",
    "resourcemanager.projects.list"
   ],
   "stage": "GA",
   "etag": "AA=="
  }
 ]
}
"""

GET_ROLES_RESPONSES = [GET_ROLES_PAGE_1,
                       GET_ROLES_PAGE_2,
                       GET_ROLES_PAGE_3]

EXPECTED_ROLE_NAMES = [
    "roles/appengine.appAdmin",
    "roles/appengine.appViewer",
    "roles/appengine.codeViewer"]

GET_PROJECT_ROLES = """
{
 "roles": [
  {
   "name": "projects/forseti-system-test/roles/customrole",
   "title": "customrole",
   "description": "Created on: 2017-11-08",
   "includedPermissions": [
    "compute.firewalls.create",
    "compute.firewalls.delete",
    "compute.firewalls.get",
    "compute.firewalls.list",
    "compute.firewalls.update",
    "compute.globalOperations.list",
    "compute.networks.updatePolicy",
    "compute.projects.get"
   ],
   "etag": "BwVdgFmZ7Dg="
  }
 ]
}
"""

EXPECTED_PROJECT_ROLE_NAMES = ["projects/forseti-system-test/roles/customrole"]

GET_ORGANIZATION_ROLES = """
{
 "roles": [
  {
   "name": "organizations/1234567890/roles/orgrole",
   "title": "orgrole",
   "description": "Created on: 2017-11-08",
   "includedPermissions": [
    "compute.firewalls.create",
    "compute.firewalls.delete",
    "compute.firewalls.get",
    "compute.firewalls.list",
    "compute.firewalls.update",
    "compute.globalOperations.list",
    "compute.networks.updatePolicy",
    "compute.projects.get"
   ],
   "etag": "BwVdgFmZ7Dg="
  }
 ]
}
"""

EXPECTED_ORGANIZATION_ROLE_NAMES = ["organizations/1234567890/roles/orgrole"]

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
