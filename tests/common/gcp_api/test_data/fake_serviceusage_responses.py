# Copyright 2019 The Forseti Security Authors. All rights reserved.
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

"""Test data for Service Usage GCP api responses."""

# list()-related test data

FAKE_PROJECT_ID = 'project1'

LIST_SERVICES_PAGE1 = """
{
"services": [
    {
    "config": {
        "authentication": {},
        "documentation": {
            "summary": "A data platform for customers to create, manage, share and query data."},
        "name": "bigquery-json.googleapis.com",
        "quota": {},
        "title": "BigQuery API",
        "usage": {"requirements": ["serviceusage.googleapis.com/tos/cloud"]}},
    "name": "projects/722027757380/services/bigquery-json.googleapis.com",
    "state": "ENABLED"
    },
    {
    "config": {
        "authentication": {},
        "documentation": {},
        "name": "bigquerystorage.googleapis.com",
        "quota": {},
        "title": "BigQuery Storage API",
        "usage": {"requirements": ["serviceusage.googleapis.com/tos/cloud"]}},
    "name": "projects/722027757380/services/bigquerystorage.googleapis.com",
    "state": "ENABLED"
    },
    {
    "config": {
        "authentication": {},
        "documentation": {
            "summary": "This is a meta service for Google Cloud APIs for convenience. Enabling this service enables all commonly used Google Cloud APIs for the project. By default, it is enabled for all projects created through Google Cloud Console and Google Cloud SDK, and should be manually enabled for all other projects that intend to use Google Cloud APIs. Note: disabling this service has no effect on other services."},
        "name": "cloudapis.googleapis.com",
        "quota": {},
        "title": "Google Cloud APIs",
        "usage": {"requirements": ["serviceusage.googleapis.com/tos/cloud"]}},
    "name": "projects/722027757380/services/cloudapis.googleapis.com",
    "state": "ENABLED"
    },
    {
    "config": {
        "authentication": {},
        "documentation": {
            "summary": "Examines the call stack and variables of a running application without stopping or slowing it down."},
        "name": "clouddebugger.googleapis.com",
        "quota": {},
        "title": "Stackdriver Debugger API",
        "usage": {"requirements": ["serviceusage.googleapis.com/tos/cloud"]}},
    "name": "projects/722027757380/services/clouddebugger.googleapis.com",
    "state": "ENABLED"
    },
    {
    "config": {
        "authentication": {},
        "documentation": {
            "summary": "Sends application trace data to Stackdriver Trace for viewing. Trace data is collected for all App Engine applications by default. Trace data from other applications can be provided using this API. This library is used to interact with the Trace API directly. If you are looking to instrument your application for Stackdriver Trace, we recommend using OpenCensus."},
        "name": "cloudtrace.googleapis.com",
        "quota": {}, "title": "Stackdriver Trace API",
        "usage": {"requirements": ["serviceusage.googleapis.com/tos/cloud"]}},
    "name": "projects/722027757380/services/cloudtrace.googleapis.com",
    "state": "ENABLED"
    }
],
"nextPageToken": "123"
}
"""

LIST_SERVICES_PAGE2 = """
{
"services": [
    {
    "config": {
    "authentication": {},
    "documentation": {
        "summary": "Creates and runs virtual machines on Google Cloud Platform."},
    "name": "compute.googleapis.com",
    "quota": {},
    "title": "Compute Engine API",
    "usage": {"requirements": ["serviceusage.googleapis.com/tos/cloud", "serviceusage.googleapis.com/billing-enabled"]}},
    "name": "projects/722027757380/services/compute.googleapis.com",
    "state": "ENABLED"
    },
    {
    "config": {
    "authentication": {},
    "documentation": {
        "summary": "Builds and manages container-based applications, powered by the open source Kubernetes technology."},
    "name": "container.googleapis.com",
    "quota": {},
    "title": "Kubernetes Engine API",
    "usage": {"requirements": ["serviceusage.googleapis.com/tos/cloud", "serviceusage.googleapis.com/billing-enabled"]}},
    "name": "projects/722027757380/services/container.googleapis.com",
    "state": "ENABLED"
    },
    {
    "config": {
    "authentication": {},
    "documentation": {
        "summary": "Google Container Registry provides secure, private Docker image storage on Google Cloud Platform. Our API follows the Docker Registry API specification, so we are fully compatible with the Docker CLI client, as well as standard tooling using the Docker Registry API."},
    "name": "containerregistry.googleapis.com",
    "quota": {},
    "title": "Container Registry API",
    "usage": {"requirements": ["serviceusage.googleapis.com/tos/cloud", "serviceusage.googleapis.com/billing-enabled"]}},
    "name": "projects/722027757380/services/containerregistry.googleapis.com",
    "state": "ENABLED"
    },
    {
    "config": {
    "authentication": {},
    "documentation": {
        "summary": "Accesses the schemaless NoSQL database to provide fully managed, robust, scalable storage for your application."},
    "name": "datastore.googleapis.com",
    "quota": {},
    "title": "Cloud Datastore API",
    "usage": {"requirements": ["serviceusage.googleapis.com/tos/cloud"]}},
    "name": "projects/722027757380/services/datastore.googleapis.com",
    "state": "ENABLED"
    },
    {"config": {
    "authentication": {},
    "documentation": {
        "summary": "Manages identity and access control for Google Cloud Platform resources, including the creation of service accounts, which you can use to authenticate to Google and make API calls."},
    "name": "iam.googleapis.com",
    "quota": {},
    "title": "Identity and Access Management (IAM) API",
    "usage": {"requirements": ["serviceusage.googleapis.com/tos/cloud"]}},
    "name": "projects/722027757380/services/iam.googleapis.com",
    "state": "ENABLED"
}
],
"nextPageToken": "456"
}
"""
LIST_SERVICES_PAGE3 = """
{
"services": [
    {
    "config": {
        "authentication": {},
        "documentation": {
            "summary": "Creates short-lived, limited-privilege credentials for IAM service accounts."},
        "name": "iamcredentials.googleapis.com",
        "quota": {},
        "title": "IAM Service Account Credentials API",
        "usage": {"requirements": ["serviceusage.googleapis.com/tos/cloud"]}},
    "name": "projects/722027757380/services/iamcredentials.googleapis.com",
    "state": "ENABLED"
    },
    {
    "config": {
        "authentication": {},
        "documentation": {
            "summary": "Writes log entries and manages your Stackdriver Logging configuration.The table entries below are presented in alphabetical order, not in order of common use. For explanations of the concepts found in the table entries, read the [Stackdriver Logging documentation](/logging/docs)."},
        "name": "logging.googleapis.com",
        "quota": {},
        "title": "Stackdriver Logging API",
        "usage": {"requirements": ["serviceusage.googleapis.com/tos/cloud"]}},
    "name": "projects/722027757380/services/logging.googleapis.com",
    "state": "ENABLED"
    },
    {
    "config": {
        "authentication": {},
        "documentation": {
            "summary": "Manages your Stackdriver Monitoring data and configurations. Most projects must be associated with a Stackdriver account, with a few exceptions as noted on the individual method pages. The table entries below are presented in alphabetical order, not in order of common use. For explanations of the concepts found in the table entries, read the [Stackdriver Monitoring documentation](/monitoring/docs)."},
        "name": "monitoring.googleapis.com",
        "quota": {},
        "title": "Stackdriver Monitoring API",
        "usage": {"requirements": ["serviceusage.googleapis.com/tos/cloud"]}},
    "name": "projects/722027757380/services/monitoring.googleapis.com",
    "state": "ENABLED"
    },
    {
    "config": {
        "authentication": {},
        "documentation": {
            "summary": "Manages OS login configuration for Google account users."},
        "name": "oslogin.googleapis.com",
        "quota": {},
        "title": "Cloud OS Login API",
        "usage": {"requirements": ["serviceusage.googleapis.com/tos/cloud"]}},
    "name": "projects/722027757380/services/oslogin.googleapis.com",
    "state": "ENABLED"
    },
    {
    "config": {
        "authentication": {},
        "documentation": {
            "summary": "Provides reliable, many-to-many, asynchronous messaging between applications."},
        "name": "pubsub.googleapis.com",
        "quota": {},
        "title": "Cloud Pub/Sub API",
        "usage": {"requirements": ["serviceusage.googleapis.com/tos/cloud"]}},
    "name": "projects/722027757380/services/pubsub.googleapis.com",
    "state": "ENABLED"
    }
],
"nextPageToken": "789"
}
"""

LIST_SERVICES_PAGE4 = """
{
"services": [
    {
    "config": {
        "authentication": {},
        "documentation": {
            "summary": "Google Service Management allows service producers to publish their services on Google Cloud Platform so that they can be discovered and used by service consumers."},
        "name": "servicemanagement.googleapis.com",
        "quota": {},
        "title": "Service Management API",
        "usage": {"requirements": ["serviceusage.googleapis.com/tos/cloud"]}},
    "name": "projects/722027757380/services/servicemanagement.googleapis.com",
    "state": "ENABLED"
    },
    {
    "config": {
        "authentication": {},
        "documentation": {
            "summary": "Enables services that service consumers want to use on Google Cloud Platform, lists the available or enabled services, or disables services that service consumers no longer use."},
        "name": "serviceusage.googleapis.com",
        "quota": {},
        "title": "Service Usage API",
        "usage": {"requirements": ["serviceusage.googleapis.com/tos/cloud"]}},
    "name": "projects/722027757380/services/serviceusage.googleapis.com",
    "state": "ENABLED"
    },
    {
    "config": {
        "authentication": {},
        "documentation": {
            "summary": "Google Cloud SQL is a hosted and fully managed relational database service on Google's infrastructure."},
        "name": "sql-component.googleapis.com",
        "quota": {},
        "title": "Cloud SQL",
        "usage": {"requirements": ["serviceusage.googleapis.com/tos/cloud"]}},
    "name": "projects/722027757380/services/sql-component.googleapis.com",
    "state": "ENABLED"
    },
    {
    "config": {
        "authentication": {},
        "documentation": {
            "summary": "Lets you store and retrieve potentially-large, immutable data objects."},
        "name": "storage-api.googleapis.com", "quota": {},
        "title": "Google Cloud Storage JSON API",
        "usage": {"requirements": ["serviceusage.googleapis.com/tos/cloud"]}},
    "name": "projects/722027757380/services/storage-api.googleapis.com",
    "state": "ENABLED"
    },
    {
    "config": {
        "authentication": {},
        "documentation": {
            "summary": "Google Cloud Storage is a RESTful service for storing and accessing your data on Google's infrastructure."},
        "name": "storage-component.googleapis.com",
        "quota": {},
        "title": "Cloud Storage",
        "usage": {"requirements": ["serviceusage.googleapis.com/tos/cloud"]}},
    "name": "projects/722027757380/services/storage-component.googleapis.com",
    "state": "ENABLED"
    }
]
}
"""

LIST_SERVICES_RESPONSES = [
    LIST_SERVICES_PAGE1,
    LIST_SERVICES_PAGE2,
    LIST_SERVICES_PAGE3,
    LIST_SERVICES_PAGE4
]

EXPECTED_SERVICES_COUNT = 20

LIST_PERMISSION_DENIED = """
{
 "error": {
  "code": 403,
  "message": "Project 'project1' not found or permission denied.",
  "status": "PERMISSION_DENIED"
 }
}
"""
