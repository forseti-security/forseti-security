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

"""Test data for Service Management GCP api responses."""

# NOTE: The ServiceManagement v1 list() API does not actually populate the
# producerProjectId of the resulting ManagedService objects.

# list()-related test data

FAKE_PROJECT_ID = 'project1'

LIST_SERVICES_PAGE1 = """
{
 "services": [
  {
   "serviceName": "bigquery-json.googleapis.com",
   "producerProjectId": "google.com:ultra-current-88221"
  },
  {
   "serviceName": "cloudbilling.googleapis.com",
   "producerProjectId": "cloud-billing-api"
  },
  {
   "serviceName": "apikeys.googleapis.com",
   "producerProjectId": "google.com:steel-binder-818"
  },
  {
   "serviceName": "appengineflex.googleapis.com",
   "producerProjectId": "google.com:gae-api-prod"
  },
  {
   "serviceName": "admin.googleapis.com",
   "producerProjectId": "google.com:api-project-73174915157"
  },
  {
   "serviceName": "cloudapis.googleapis.com",
   "producerProjectId": "google.com:cloudapis-producer"
  }
 ],
 "nextPageToken": "123"
}
"""

LIST_SERVICES_PAGE2 = """
{
 "services": [
  {
   "serviceName": "containerregistry.googleapis.com",
   "producerProjectId": "containerregistry"
  },
  {
   "serviceName": "cloudtrace.googleapis.com",
   "producerProjectId": "cloud-trace-api-producer"
  },
  {
   "serviceName": "container.googleapis.com",
   "producerProjectId": "google.com:cloud-kubernetes-devrel"
  },
  {
   "serviceName": "containeranalysis.googleapis.com",
   "producerProjectId": "container-analysis"
  },
  {
   "serviceName": "dataproc-control.googleapis.com",
   "producerProjectId": "cloud-dataproc-producer"
  },
  {
   "serviceName": "clouddebugger.googleapis.com",
   "producerProjectId": "google.com:cloud-debugger-producer"
  },
  {
   "serviceName": "compute.googleapis.com",
   "producerProjectId": "google.com:api-project-539346026206"
  },
  {
   "serviceName": "cloudbuild.googleapis.com",
   "producerProjectId": "argo-api-producer"
  }
 ],
 "nextPageToken": "456"
}
"""

LIST_SERVICES_PAGE3 = """
{
 "services": [
  {
   "serviceName": "deploymentmanager.googleapis.com",
   "producerProjectId": "google.com:api-project-596022999904"
  },
  {
   "serviceName": "pubsub.googleapis.com",
   "producerProjectId": "cloud-pubsub-billing"
  },
  {
   "serviceName": "dataproc.googleapis.com",
   "producerProjectId": "cloud-dataproc-producer"
  },
  {
   "serviceName": "monitoring.googleapis.com",
   "producerProjectId": "google.com:gcm-api-admin"
  },
  {
   "serviceName": "dns.googleapis.com",
   "producerProjectId": "cloud-dns-service-config"
  },
  {
   "serviceName": "logging.googleapis.com",
   "producerProjectId": "metal-incline-93520"
  },
  {
   "serviceName": "datastore.googleapis.com",
   "producerProjectId": "cloud-datastore-api"
  },
  {
   "serviceName": "replicapool.googleapis.com",
   "producerProjectId": "google.com:api-project-861046436738"
  },
  {
   "serviceName": "replicapoolupdater.googleapis.com",
   "producerProjectId": "google.com:prod-default-producer-project"
  },
  {
   "serviceName": "iam.googleapis.com",
   "producerProjectId": "iam-whitelisting-project"
  }
 ],
 "nextPageToken": "789"
}
"""

LIST_SERVICES_PAGE4 = """
{
 "services": [
  {
   "serviceName": "servicemanagement.googleapis.com",
   "producerProjectId": "google.com:steel-binder-818"
  },
  {
   "serviceName": "storage-api.googleapis.com",
   "producerProjectId": "cloud-storage-producer"
  },
  {
   "serviceName": "storage.googleapis.com",
   "producerProjectId": "cloud-storage-producer"
  },
  {
   "serviceName": "resourceviews.googleapis.com",
   "producerProjectId": "google.com:prod-default-producer-project"
  },
  {
   "serviceName": "sql-component.googleapis.com",
   "producerProjectId": "google.com:prod-default-producer-project"
  },
  {
   "serviceName": "storage-component.googleapis.com",
   "producerProjectId": "google.com:prod-default-producer-project"
  }
 ]
}
"""

LIST_CONSUMER_SERVICES_RESPONSES = [
    LIST_SERVICES_PAGE1,
    LIST_SERVICES_PAGE2,
    LIST_SERVICES_PAGE3,
    LIST_SERVICES_PAGE4
]

LIST_PRODUCER_SERVICES_RESPONSES = [
    LIST_SERVICES_PAGE3,
    LIST_SERVICES_PAGE4
]

LIST_ALL_SERVICES_RESPONSES = [
    LIST_SERVICES_PAGE1,
    LIST_SERVICES_PAGE2,
    LIST_SERVICES_PAGE3,
    LIST_SERVICES_PAGE4
]

EXPECTED_CONSUMER_SERVICES_COUNT = 30
EXPECTED_PRODUCER_SERVICES_COUNT = 16
EXPECTED_ALL_SERVICES_COUNT = 30


# IAM Policy test data

FAKE_SERVICE_NAME = 'foo.googleapis.com'

GET_API_IAM_POLICY_RESPONSE = """
{
 "etag": "etag",
 "bindings": [
  {
   "role": "roles/owner",
   "members": [
    "user:testuser@foo.testing"
   ]
  },
  {
   "role": "roles/editor",
   "members": [
    "user:testuser2@foo.testing",
    "user:testuser3@foo.testing"
   ]
  }
 ]
}
"""

EXPECTED_IAM_POLICY_BINDINGS_COUNT = 2

LIST_PERMISSION_DENIED = """
{
 "error": {
  "code": 403,
  "message": "Project 'project1' not found or permission denied.",
  "status": "PERMISSION_DENIED"
 }
}
"""

IAM_PERMISSION_DENIED = """
{
 "error": {
  "code": 403,
  "message": "No access to resource: services/foo.googleapis.com"
  "status": "PERMISSION_DENIED"
 }
}
"""
