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

"""Test data for appengine GCP api responses."""

FAKE_PROJECT_ID = "forseti-system-test"
FAKE_APP_NAME = "apps/forseti-system-test"
FAKE_SERVICE_ID = "default"
FAKE_VERSION_ID = "20170911t154822"
FAKE_INSTANCE_ID = ("00112233445566778899aabbccddeeff01112233445566778899"
                    "aabbccddeeff0211223344")

FAKE_APP_GET_RESPONSE = """
{
 "name": "apps/forseti-system-test",
 "id": "forseti-system-test",
 "authDomain": "forseti.testing",
 "locationId": "us-central",
 "codeBucket": "staging.forseti-system-test.a.b.c",
 "servingStatus": "SERVING",
 "defaultHostname": "forseti-system-test.a.b.c",
 "defaultBucket": "forseti-system-test.a.b.c",
 "gcrDomain": "us.gcr.io"
}
"""

LIST_SERVICES_RESPONSE = """
{
  "services": [
    {
      "name": "apps/forseti-system-test/services/default",
      "id": "default",
      "split": {
        "allocations": {
          "20170118t111213": 1
        }
      }
    }
  ]
}
"""

GET_SERVICE_RESPONSE = """
{
  "name": "apps/forseti-system-test/services/default",
  "id": "default",
  "split": {
    "allocations": {
      "20170911t154822": 1
    }
  }
}
"""

EXPECTED_SERVICE_NAMES = [
    "apps/forseti-system-test/services/default"]

LIST_VERSIONS_RESPONSE_PAGE1 = """
{
  "versions": [
    {
      "name": "apps/forseti-system-test/services/default/versions/20170911t154822",
      "id": "20170911t154822",
      "instanceClass": "F1",
      "runtime": "python27",
      "threadsafe": true,
      "env": "standard",
      "servingStatus": "SERVING",
      "createdBy": "user1@forseti.testing",
      "createTime": "2017-09-11T22:48:32Z",
      "diskUsageBytes": "2036",
      "versionUrl": "https://20170911t154822-dot-forseti.security.testing"
    },
    {
      "name": "apps/forseti-system-test/services/default/versions/20170118t111213",
      "id": "20170118t111213",
      "automaticScaling": {
        "coolDownPeriod": "120s",
        "cpuUtilization": {
          "targetUtilization": 0.5
        },
        "maxTotalInstances": 20,
        "minTotalInstances": 2
      },
      "runtime": "python",
      "threadsafe": true,
      "betaSettings": {
        "use_deployment_manager": "true",
        "no_appserver_affinity": "true",
        "module_yaml_path": "app.yaml",
        "has_docker_image": "true"
      },
      "env": "flexible",
      "servingStatus": "SERVING",
      "createdBy": "user1@forseti.testing",
      "createTime": "2017-01-18T18:58:57Z",
      "versionUrl": "https://20170118t111213-dot-forseti.security.testing"
    },
    {
      "name": "apps/forseti-system-test/services/default/versions/20170118t110301",
      "id": "20170118t110301",
      "runtime": "python",
      "threadsafe": true,
      "betaSettings": {
        "use_deployment_manager": "true",
        "no_appserver_affinity": "true",
        "module_yaml_path": "app.yaml",
        "has_docker_image": "true"
      },
      "env": "flexible",
      "servingStatus": "SERVING",
      "createdBy": "user1@forseti.testing",
      "createTime": "2017-01-18T19:03:34Z",
      "versionUrl": "https://20170118t110301-dot-forseti.security.testing"
    }
  ],
  "nextPageToken": "123"
}
"""

LIST_VERSIONS_RESPONSE_PAGE2 = """
{
  "versions": [
    {
      "name": "apps/forseti-system-test/services/default/versions/20170118t110929",
      "id": "20170118t110929",
      "runtime": "python",
      "threadsafe": true,
      "betaSettings": {
        "use_deployment_manager": "true",
        "no_appserver_affinity": "true",
        "module_yaml_path": "app.yaml",
        "has_docker_image": "true"
      },
      "env": "flexible",
      "servingStatus": "SERVING",
      "createdBy": "user1@forseti.testing",
      "createTime": "2017-01-18T19:10:05Z",
      "versionUrl": "https://20170118t110929-dot-forseti.security.testing"
    },
    {
      "name": "apps/forseti-system-test/services/default/versions/test-deploy",
      "id": "test-deploy",
      "runtime": "python",
      "threadsafe": true,
      "betaSettings": {
        "use_deployment_manager": "true",
        "no_appserver_affinity": "true",
        "module_yaml_path": "app.yaml",
        "has_docker_image": "true"
      },
      "env": "flexible",
      "servingStatus": "SERVING",
      "createdBy": "user1@forseti.testing",
      "createTime": "2017-02-02T17:09:21Z",
      "versionUrl": "https://test-deploy-dot-forseti.security.testing"
    }
  ]
}
"""

LIST_VERSIONS_RESPONSES = [LIST_VERSIONS_RESPONSE_PAGE1,
                           LIST_VERSIONS_RESPONSE_PAGE2]

EXPECTED_VERSION_NAMES = [
    "apps/forseti-system-test/services/default/versions/20170911t154822",
    "apps/forseti-system-test/services/default/versions/20170118t111213",
    "apps/forseti-system-test/services/default/versions/20170118t110301",
    "apps/forseti-system-test/services/default/versions/20170118t110929",
    "apps/forseti-system-test/services/default/versions/test-deploy"]

GET_VERSION_RESPONSE = """
{
  "name": "apps/forseti-system-test/services/default/versions/20170911t154822",
  "id": "20170911t154822",
  "instanceClass": "F1",
  "runtime": "python27",
  "threadsafe": true,
  "env": "standard",
  "servingStatus": "SERVING",
  "createdBy": "user1@forseti.testing",
  "createTime": "2017-09-11T22:48:32Z",
  "diskUsageBytes": "2036",
  "versionUrl": "https://20170911t154822-dot-forseti.security.testing"
}
"""

LIST_INSTANCES_RESPONSE = """
{
  "instances": [
    {
      "name": "apps/forseti-system-test/services/default/versions/20170911t154822/instances/00112233445566778899aabbccddeeff01112233445566778899aabbccddeeff0211223344",
      "id": "00112233445566778899aabbccddeeff01112233445566778899aabbccddeeff0211223344",
      "appEngineRelease": "1.9.54",
      "availability": "DYNAMIC",
      "startTime": "2017-09-11T22:49:03.485539Z",
      "requests": 3,
      "memoryUsage": "22802432"
    }
  ]
}
"""

EXPECTED_INSTANCE_NAMES = [
    "apps/forseti-system-test/services/default/versions/20170911t154822/"
    "instances/00112233445566778899aabbccddeeff01112233445566778899aabbccddeeff"
    "0211223344"
]

GET_INSTANCE_RESPONSE = """
{
  "name": "apps/forseti-system-test/services/default/versions/20170911t154822/instances/00112233445566778899aabbccddeeff01112233445566778899aabbccddeeff0211223344",
  "id": "00112233445566778899aabbccddeeff01112233445566778899aabbccddeeff0211223344",
  "appEngineRelease": "1.9.54",
  "availability": "DYNAMIC",
  "startTime": "2017-09-11T22:49:03.485539Z",
  "requests": 3,
  "memoryUsage": "22802432"
}
"""


# Errors

APP_NOT_FOUND = """
{
 "error": {
  "code": 404,
  "message": "Could not find Application 'forseti-system-test'.",
  "status": "NOT_FOUND"
 }
}
"""

PERMISSION_DENIED = """
{
 "error": {
  "code": 403,
  "message": "Operation not allowed",
  "status": "PERMISSION_DENIED"
 }
}
"""

