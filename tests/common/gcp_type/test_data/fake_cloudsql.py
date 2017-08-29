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

"""Fake cloudsql data."""

import copy

FAKE_EMPTY_RESPONSE = """
{
 "kind": "sql#instancesList"
}
"""

PROJECT_INVALID = """
{
 "error": {
  "errors": [
   {
    "domain": "global",
    "reason": "errorInvalidProject",
    "message": "Project specified in the request is invalid."
   }
  ],
  "code": 400,
  "message": "Project specified in the request is invalid."
 }
}
"""

FAKE_CLOUDSQL_RESPONSE = {
  u'items': [{u'backendType': u'SECOND_GEN',
             u'connectionName': u'project-1:us-east1:cloudsql-instance',
             u'databaseVersion': u'MYSQL_5_7',
             u'etag': u'"CAE="',
             u'instanceType': u'CLOUD_SQL_INSTANCE',
             u'ipAddresses': [{u'ipAddress': u'1.2.3.4',
                               u'type': u'PRIMARY'}],
             u'kind': u'sql#instance',
             u'name': u'cloudsql-instance',
             u'project': u'project-1',
             u'region': u'us-east1',
             u'selfLink': u'https://www.googleapis.com/sql/v1beta4/projects/project-1/instances/cloudsql-instance',
             u'serverCaCert': {u'cert': u'-----BEGIN CERTIFICATE-----\nc29ycnk=\n-----END CERTIFICATE-----',
                               u'certSerialNumber': u'0',
                               u'commonName': u'C=US,O=Google\\, Inc,CN=Google Cloud SQL Server CA',
                               u'createTime': u'2016-09-01T11:11:11.111Z',
                               u'expirationTime': u'2018-09-01T11:11:11.111Z',
                               u'instance': u'cloudsql-instance',
                               u'kind': u'sql#sslCert',
                               u'sha1Fingerprint': u'8cb2237d0679ca88db6464eac60da96345513964'},
             u'serviceAccountEmailAddress': u'serviceaccount1@iam.gserviceaccount.com',
             u'settings': {u'activationPolicy': u'ALWAYS',
                           u'authorizedGaeApplications': [],
                           u'backupConfiguration': {u'binaryLogEnabled': True,
                                                    u'enabled': True,
                                                    u'kind': u'sql#backupConfiguration',
                                                    u'startTime': u'03:00'},
                           u'dataDiskSizeGb': u'10',
                           u'dataDiskType': u'PD_SSD',
                           u'ipConfiguration': {u'authorizedNetworks': [],
                                                u'ipv4Enabled': True,
                                                u'requireSsl': True},
                           u'kind': u'sql#settings',
                           u'pricingPlan': u'PER_USE',
                           u'replicationType': u'SYNCHRONOUS',
                           u'settingsVersion': u'28',
                           u'storageAutoResize': False,
                           u'storageAutoResizeLimit': u'0',
                           u'tier': u'db-n1-standard-1'},
             u'state': u'RUNNABLE'},
            {u'backendType': u'SECOND_GEN',
             u'connectionName': u'project-1:europe-west1:test-forseti',
             u'databaseVersion': u'MYSQL_5_7',
             u'etag': u'"CAE="',
             u'instanceType': u'CLOUD_SQL_INSTANCE',
             u'ipAddresses': [{u'ipAddress': u'4.3.2.1',
                               u'type': u'PRIMARY'}],
             u'kind': u'sql#instance',
             u'name': u'test-forseti',
             u'project': u'project-1',
             u'region': u'europe-west1',
             u'selfLink': u'https://www.googleapis.com/sql/v1beta4/projects/project-1/instances/test-forseti',
             u'serverCaCert': {u'cert': u'-----BEGIN CERTIFICATE-----\nnc29ycnk\n-----END CERTIFICATE-----',
                               u'certSerialNumber': u'0',
                               u'commonName': u'C=US,O=Google\\, Inc,CN=Google Cloud SQL Server CA',
                               u'createTime': u'2017-03-04T22:22:22.222Z',
                               u'expirationTime': u'2019-03-04T22:22:22.222Z',
                               u'instance': u'test-forseti',
                               u'kind': u'sql#sslCert',
                               u'sha1Fingerprint': u'348162101fc6f7e624681b7400b085eeac6df7bd'},
             u'serviceAccountEmailAddress': u'serviceaccount2@iam.gserviceaccount.com',
             u'settings': {u'activationPolicy': u'ALWAYS',
                           u'authorizedGaeApplications': [],
                           u'backupConfiguration': {u'binaryLogEnabled': False,
                                                    u'enabled': False,
                                                    u'kind': u'sql#backupConfiguration',
                                                    u'startTime': u'03:00'},
                           u'dataDiskSizeGb': u'250',
                           u'dataDiskType': u'PD_SSD',
                           u'ipConfiguration': {u'authorizedNetworks': [{u'kind': u'sql#aclEntry',
                                                                         u'name': u'test',
                                                                         u'value': u'0.0.0.0/0'}],
                                                u'ipv4Enabled': True},
                           u'kind': u'sql#settings',
                           u'maintenanceWindow': {u'day': 0,
                                                  u'hour': 0,
                                                  u'kind': u'sql#maintenanceWindow'},
                           u'pricingPlan': u'PER_USE',
                           u'replicationType': u'SYNCHRONOUS',
                           u'settingsVersion': u'6',
                           u'storageAutoResize': True,
                           u'storageAutoResizeLimit': u'0',
                           u'tier': u'db-n1-standard-1'},
             u'state': u'RUNNABLE'},
            {u'backendType': u'SECOND_GEN',
             u'connectionName': u'project-1:us-central1:forsetitest-2',
             u'databaseVersion': u'MYSQL_5_7',
             u'etag': u'"CAE="',
             u'instanceType': u'CLOUD_SQL_INSTANCE',
             u'ipAddresses': [{u'ipAddress': u'192.168.1.2',
                               u'type': u'PRIMARY'}],
             u'kind': u'sql#instance',
             u'name': u'forsetitest-2',
             u'project': u'project-1',
             u'region': u'us-central1',
             u'selfLink': u'https://www.googleapis.com/sql/v1beta4/projects/project-1/instances/forsetitest-2',
             u'serverCaCert': {u'cert': u'-----BEGIN CERTIFICATE-----\nnc29ycnk\n-----END CERTIFICATE-----',
                               u'certSerialNumber': u'0',
                               u'commonName': u'C=US,O=Google\\, Inc,CN=Google Cloud SQL Server CA',
                               u'createTime': u'2017-01-22T00:00:20.999Z',
                               u'expirationTime': u'2019-01-22T00:00:20.999Z',
                               u'instance': u'forsetitest-2',
                               u'kind': u'sql#sslCert',
                               u'sha1Fingerprint': u'b6589fc6ab0dc82cf12099d1c2d40ab994e8410c'},
             u'serviceAccountEmailAddress': u'serviceaccount3@iam.gserviceaccount.com',
             u'settings': {u'activationPolicy': u'ALWAYS',
                           u'authorizedGaeApplications': [],
                           u'backupConfiguration': {u'binaryLogEnabled': True,
                                                    u'enabled': True,
                                                    u'kind': u'sql#backupConfiguration',
                                                    u'startTime': u'11:00'},
                           u'dataDiskSizeGb': u'25',
                           u'dataDiskType': u'PD_HDD',
                           u'ipConfiguration': {u'authorizedNetworks': [{u'kind': u'sql#aclEntry',
                                                                         u'name': u'127.7.7.7',
                                                                         u'value': u'127.0.214.3/32'}],
                                                u'ipv4Enabled': True},
                           u'kind': u'sql#settings',
                           u'maintenanceWindow': {u'day': 0,
                                                  u'hour': 0,
                                                  u'kind': u'sql#maintenanceWindow'},
                           u'pricingPlan': u'PER_USE',
                           u'replicationType': u'SYNCHRONOUS',
                           u'settingsVersion': u'57',
                           u'storageAutoResize': True,
                           u'storageAutoResizeLimit': u'0',
                           u'tier': u'db-n1-standard-1'},
             u'state': u'RUNNABLE'}],
 u'kind': u'sql#instancesList'}


EXPECTED_FAKE_CLOUDSQL_FROM_API = copy.deepcopy(
    FAKE_CLOUDSQL_RESPONSE.get('items'))
