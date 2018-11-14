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

GET_PROJECT_ANCESTRY_RESPONSE = """
{
 "ancestor": [
  {
   "resourceId": {
    "type": "project",
    "id": "forseti-system-test"
   }
  },
  {
   "resourceId": {
    "type": "folder",
    "id": "3333333"
   }
  },
  {
   "resourceId": {
    "type": "organization",
    "id": "2222222"
   }
  }
 ]
}
"""

EXPECTED_PROJECT_ANCESTRY_IDS = ["forseti-system-test", "3333333", "2222222"]

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

SEARCH_ORGANIZATIONS_PAGE1 = """
{
 "organizations": [
  {
   "displayName": "foresti.testing",
   "owner": {
    "directoryCustomerId": "ABC123DEF"
   },
   "creationTime": "2015-09-09T19:34:18.591Z",
   "lifecycleState": "ACTIVE",
   "name": "organizations/2222222"
  }
 ],
 "nextPageToken": "123"
}
"""

SEARCH_ORGANIZATIONS_PAGE2 = """
{
 "organizations": [
  {
   "displayName": "test.foresti.testing",
   "owner": {
    "directoryCustomerId": "FED987CBA"
   },
   "creationTime": "2016-01-09T09:30:28.001Z",
   "lifecycleState": "ACTIVE",
   "name": "organizations/4444444"
  }
 ]
}
"""

SEARCH_ORGANIZATIONS = [SEARCH_ORGANIZATIONS_PAGE1,
                        SEARCH_ORGANIZATIONS_PAGE2]

EXPECTED_ORGANIZATIONS_FROM_SEARCH = ["organizations/2222222",
                                      "organizations/4444444"]

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

GET_ORG_POLICY_NO_POLICY = """
{
  "constraint": "constraints/compute.disableSerialPortAccess",
  "etag": "BwVUSr8Q7Ng="
}
"""

GET_EFFECTIVE_ORG_POLICY = """
{
  "constraint": "constraints/compute.disableSerialPortAccess",
  "booleanPolicy": {
   "enforced": true
  }
}
"""

GET_LIENS = """
{
  "liens": [
    {
      "name": "liens/test-lien1",
      "parent": "projects/forseti-system-test",
      "restrictions": [
        "resourcemanager.projects.delete"
      ],
      "origin": "testing",
      "createTime": "2018-09-05T14:45:46.534Z"
    }
  ]
}
"""

EXPECTED_LIENS = [{
    "name": "liens/test-lien1",
    "parent": "projects/forseti-system-test",
    "restrictions": [
        "resourcemanager.projects.delete"
    ],
    "origin": "testing",
    "createTime": "2018-09-05T14:45:46.534Z"
}]

LIST_ORG_POLICIES = """
{
 "policies": [
  {
    "constraint": "constraints/compute.disableSerialPortAccess",
    "booleanPolicy": {
     "enforced": true
    }
  }
 ]
}
"""

TEST_ORG_POLICY_CONSTRAINT = "constraints/compute.disableSerialPortAccess"

FAKE_FOLDERS_API_RESPONSE1 = {
    'folders': [
        {
            'displayName': 'folder-1',
            'name': 'folders/111',
            'lifecycleState': 'ACTIVE',
            'parent': 'organizations/9999'
        },
        {
            'displayName': 'folder-2',
            'name': 'folders/222',
            'parent': 'folders/2222222',
            'lifecycleState': 'DELETE_REQUESTED'
        },
        {
            'displayName': 'folder-3',
            'name': 'folders/333',
            'parent': 'folders/3333333',
            'lifecycleState': 'ACTIVE'
        },
    ]
}

EXPECTED_FAKE_FOLDERS1 = FAKE_FOLDERS_API_RESPONSE1['folders']

FAKE_FOLDERS_LIST_API_RESPONSE1 = {
    'folders': [
        f for f in FAKE_FOLDERS_API_RESPONSE1['folders']
            if f['parent'] == 'organizations/9999'
    ]
}

EXPECTED_FAKE_FOLDERS_LIST1 = FAKE_FOLDERS_LIST_API_RESPONSE1['folders']

FAKE_ACTIVE_FOLDERS_API_RESPONSE1 = {
    'folders': [
        f for f in FAKE_FOLDERS_API_RESPONSE1['folders']
            if f['lifecycleState'] == 'ACTIVE'
    ]
}

EXPECTED_FAKE_ACTIVE_FOLDERS1 = FAKE_ACTIVE_FOLDERS_API_RESPONSE1['folders']

FAKE_ORGS_RESPONSE = {
    'organizations': [
        {
            'name': 'organizations/1111111111',
            'display_name': 'Organization1',
            'lifecycleState': 'ACTIVE',
        },
        {
            'name': 'organizations/2222222222',
            'display_name': 'Organization2',
            'lifecycleState': 'ACTIVE',
        },
        {
            'name': 'organizations/3333333333',
            'display_name': 'Organization3',
            'lifecycleState': 'ACTIVE',
        }
    ]
}

EXPECTED_FAKE_ORGS_FROM_API = FAKE_ORGS_RESPONSE['organizations']

FAKE_PROJECTS_API_RESPONSE1 = {
    'projects': [
        {
            'name': 'project1',
            'projectId': 'project1',
            'projectNumber': '25621943694',
            'lifecycleState': 'ACTIVE',
        },
        {
            'name': 'project2',
            'projectId': 'project2',
            'projectNumber': '94226340476',
            'lifecycleState': 'DELETE_REQUESTED',
        },
        {
            'name': 'project3',
            'projectId': 'project3',
            'projectNumber': '133851422272',
            'lifecycleState': 'ACTIVE',
        }]
}

EXPECTED_FAKE_PROJECTS_API_RESPONSE1_IDS = [u'project1', u'project2', u'project3']

FAKE_ACTIVE_PROJECTS_API_RESPONSE = {
    'projects': [
        p for p in FAKE_PROJECTS_API_RESPONSE1['projects']
        if p['lifecycleState'] == 'ACTIVE'
    ]
}

EXPECTED_FAKE_PROJECTS1 = [FAKE_PROJECTS_API_RESPONSE1]

EXPECTED_FAKE_ACTIVE_PROJECTS1 = [{
    'projects': [
        p for p in FAKE_PROJECTS_API_RESPONSE1['projects']
            if p['lifecycleState'] == 'ACTIVE'
    ]
}]

# Errors

GET_PROJECT_NOT_FOUND = """
{
 "error": {
  "code": 403,
  "message": "The caller does not have permission",
  "status": "PERMISSION_DENIED"
 }
}
"""
