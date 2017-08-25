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

APP_NOT_FOUND = """
{
 "error": {
  "code": 404,
  "message": "Could not find Application \"ahoying-dev-test\".",
  "status": "NOT_FOUND"
 }
}
"""

PERMISSION_DENIED = """
{
 "error": {
  "code": 403,
  "message": "Operation not allowed",
  "status": "PERMISSION_DENIED",
 }
}
"""
