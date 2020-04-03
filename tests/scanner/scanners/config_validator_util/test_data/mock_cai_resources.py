# Copyright 2020 The Forseti Security Authors. All rights reserved.
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

BUCKET_DATA = {
  "acl": [],
  "billing": {},
  "cors": [],
  "defaultObjectAcl": [],
  "encryption": {},
  "etag": "CAE=",
  "iamConfiguration": {
    "bucketPolicyOnly": {
      "enabled": True,
      "lockedTime": "2020-06-01T21:47:31.850Z"
    },
    "uniformBucketLevelAccess": {
      "enabled": True,
      "lockedTime": "2020-06-01T21:47:31.850Z"
    }
  },
  "id": "test-bucket-123",
  "kind": "storage#bucket",
  "labels": {},
  "lifecycle": {
    "rule": []
  },
  "location": "US-CENTRAL1",
  "locationType": "region",
  "logging": {},
  "metageneration": 1,
  "name": "test-bucket-123",
  "owner": {},
  "projectNumber": 1234567890,
  "retentionPolicy": {},
  "selfLink": "https://www.googleapis.com/storage/v1/b/test-bucket-123",
  "storageClass": "STANDARD",
  "timeCreated": "2020-03-03T21:47:31.850Z",
  "updated": "2020-03-03T21:47:31.850Z",
  "versioning": {},
  "website": {},
  "zoneAffinity": []
}

FIREWALL_DATA = {
  "allowed": [
    {
      "IPProtocol": "tcp"
    }
  ],
  "creationTimestamp": "2020-02-26T21:29:36.754-08:00",
  "description": "Test",
  "direction": "INGRESS",
  "disabled": False,
  "id": "1234567890123456789",
  "logConfig": {
    "enable": False
  },
  "name": "firewall-allow-all-ingress-123",
  "network": "https://www.googleapis.com/compute/v1/projects/test-project-123/global/networks/default",
  "priority": 1000,
  "selfLink": "https://www.googleapis.com/compute/v1/projects/test-project-123/global/firewalls/firewall-allow-all-ingress-123",
  "sourceRanges": [
    "0.0.0.0/0"
  ]
}
