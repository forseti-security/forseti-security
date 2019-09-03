# Copyright 2018 The Forseti Security Authors. All rights reserved.
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

"""Test data for Stackdriver Logging GCP api responses."""

FAKE_ORG_ID = '1234567890'
FAKE_FOLDER_ID = '987'
FAKE_BILLING_ACCOUNT_ID = '1234-56789'
FAKE_PROJECT_ID = 'forseti-system-test'

GET_SINKS_PAGE_1 = """
{
  "sinks": [
    {
      "name": "a-log-sink",
      "destination": "bigquery.googleapis.com/projects/some-logs-project/datasets/audit_logs",
      "filter": "logName:\\\"logs/cloudaudit.googleapis.com\\\"",
      "outputVersionFormat": "V2",
      "writerIdentity": "serviceAccount:a-log-sink@logging-123456789.iam.gserviceaccount.com"
    }
  ],
  "nextPageToken": "token1"
}
"""

GET_SINKS_PAGE_2 = """
{
  "sinks": [
    {
      "name": "another-log-sink",
      "destination": "storage.googleapis.com/big-logs-bucket",
      "outputVersionFormat": "V2",
      "writerIdentity": "serviceAccount:p12345-67890@gcp-sa-logging.iam.gserviceaccount.com"
    }
  ],
  "nextPageToken": "token2"
}
"""

GET_SINKS_PAGE_3 = """
{
  "sinks": [
    {
      "name": "final-log-sink",
      "destination": "pubsub.googleapis.com/projects/forseti-test/topics/forseti-logs",
      "filter": "resource.type=\\\"gce_instancet\\\"\\nresource.labels.instance_id=\\\"1122332211\\\"",
      "outputVersionFormat": "V2",
      "includeChildren": true,
      "writerIdentity": "serviceAccount:cloud-logs@system.gserviceaccount.com"
    }
  ]
}
"""

GET_SINKS_RESPONSES = [GET_SINKS_PAGE_1,
                       GET_SINKS_PAGE_2,
                       GET_SINKS_PAGE_3]

EXPECTED_SINK_NAMES = [
    'a-log-sink',
    'another-log-sink',
    'final-log-sink']

NOT_FOUND = """
{
 "error": {
  "code": 404,
  "message": "Project does not exist: missing-project",
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
