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
"""Mock responses to GCP API calls, for testing.

When updating this file, also update the model test database by running
tests/services/model/importer/update_test_dbs.py.
"""

import json

ORGANIZATION_ID = "organizations/111222333"
FOLDER_ID = "folders/444555666"

GSUITE_CUSTOMER_ID = "ABC123DEF"

# Every resource needs a unique ID prefix so that every generated resource
# has a unique ID.
USER_ID_PREFIX = "100"
GROUP_ID_PREFIX = "101"
GROUP_MEMBER_ID_PREFIX = "102"
FOLDER_ID_PREFIX = "103"
PROJECT_ID_PREFIX = "104"
GCE_PROJECT_ID_PREFIX = "105"
GCE_INSTANCE_ID_PREFIX = "106"
FIREWALL_ID_PREFIX = "107"
INSTANCE_GROUP_ID_PREFIX = "108"
BACKEND_SERVICE_ID_PREFIX = "109"
SERVICEACCOUNT_ID_PREFIX = "110"
FORWARDING_RULE_ID_PREFIX = "111"
INSTANCE_GROUP_MANAGER_ID_PREFIX = "112"
INSTANCE_TEMPLATE_ID_PREFIX = "113"
NETWORK_ID_PREFIX = "114"
SUBNETWORK_ID_PREFIX = "115"
SERVICEACCOUNT_KEY_ID_PREFIX = "116"
GCE_IMAGE_ID_PREFIX = "117"
GCE_DISK_ID_PREFIX = "118"
SNAPSHOT_ID_PREFIX = "119"
LIEN_ID_PREFIX = "120"

# Fields: id, email, name
AD_USER_TEMPLATE = """
{{
 "kind": "admin#directory#user",
 "id": "100{id}",
 "primaryEmail": "{email}",
 "name": {{
  "fullName": "{name}"
 }},
 "emails": [
  {{
   "address": "{email}",
   "primary": true
  }}
 ]
}}
"""

AD_GET_USERS = {
    GSUITE_CUSTOMER_ID: [
        json.loads(
            AD_USER_TEMPLATE.format(
                id=1, email="a_user@forseti.test", name="A User")),
        json.loads(
            AD_USER_TEMPLATE.format(
                id=2, email="b_user@forseti.test", name="B User")),
        json.loads(
            AD_USER_TEMPLATE.format(
                id=3, email="c_user@forseti.test", name="C User")),
        json.loads(
            # Note: SQLite's varchar is case sensitive and MySQL is not
            # so this test case is not useful while running SQLite.
            # This is here for future reference.
            AD_USER_TEMPLATE.format(
                id=4, email="a_USER@forseti.test", name="A User")),
    ]
}

# Fields: email, name, members, id
AD_GROUP_TEMPLATE = """
{{
 "nonEditableAliases": ["{email}"],
 "kind": "admin#directory#group",
 "name": "{name}",
 "adminCreated": true,
 "directMembersCount": "{members}",
 "email": "{email}",
 "id": "101{id}",
 "description": ""
}}
"""

AD_GET_GROUPS = {
    GSUITE_CUSTOMER_ID: [
        json.loads(
            AD_GROUP_TEMPLATE.format(
                id=1, email="a_grp@forseti.test", name="A Group", members=1)),
        json.loads(
            AD_GROUP_TEMPLATE.format(
                id=2, email="b_grp@forseti.test", name="B Group", members=1)),
        json.loads(
            AD_GROUP_TEMPLATE.format(
                id=3, email="c_grp@forseti.test", name="C Group", members=2)),
        # Duplicate groups
        json.loads(
            AD_GROUP_TEMPLATE.format(
                id=1, email="a_grp@forseti.test", name="A Group", members=1)),
        json.loads(
            AD_GROUP_TEMPLATE.format(
                id=4, email="a_GRP@forseti.test", name="A Group", members=1)),
    ]
}

# Fields: id, email, type
AD_GROUP_MEMBER_TEMPLATE = """
{{
 "kind": "admin#directory#member",
 "id": "102{id}",
 "email": "{email}",
 "role": "MEMBER",
 "type": "{type}",
 "status": "ACTIVE"
}}
"""

AD_GET_GROUP_MEMBERS = {
    GROUP_ID_PREFIX + "1": [
        json.loads(
            AD_GROUP_MEMBER_TEMPLATE.format(
                id=1, email="a_user@forseti.test", type="USER")),
        # Duplicate group member
        json.loads(
            AD_GROUP_MEMBER_TEMPLATE.format(
                id=1, email="a_user@forseti.test", type="USER"))
    ],
    GROUP_ID_PREFIX + "2": [
        json.loads(
            AD_GROUP_MEMBER_TEMPLATE.format(
                id=2, email="b_user@forseti.test", type="USER"))
    ],
    GROUP_ID_PREFIX + "3": [
        json.loads(
            AD_GROUP_MEMBER_TEMPLATE.format(
                id=3, email="c_user@forseti.test", type="USER")),
        json.loads(
            AD_GROUP_MEMBER_TEMPLATE.format(
                id=5, email="b_grp@forseti.test", type="GROUP")),
    ],
    GROUP_ID_PREFIX + "4": [
        json.loads(
            AD_GROUP_MEMBER_TEMPLATE.format(
                id=3, email="c_user@forseti.test", type="USER")),
        json.loads(
            AD_GROUP_MEMBER_TEMPLATE.format(
                id=5, email="b_grp@forseti.test", type="GROUP")),
    ],
}

# Fields: project
APPENGINE_APP_TEMPLATE = """
{{
 "name": "apps/{project}",
 "id": "{project}",
 "authDomain": "forseti.test",
 "locationId": "us-central",
 "codeBucket": "staging.{project}.a.b.c",
 "servingStatus": "SERVING",
 "defaultHostname": "{project}.a.b.c",
 "defaultBucket": "{project}.a.b.c",
 "gcrDomain": "us.gcr.io"
}}
"""

GAE_GET_APP = {
    "project3": json.loads(
        APPENGINE_APP_TEMPLATE.format(
            project="project3")),
    "project4": json.loads(
        APPENGINE_APP_TEMPLATE.format(
            project="project4")),
}

# Fields: project, service, version
APPENGINE_SERVICE_TEMPLATE = """
{{
 "name": "apps/{project}/services/{service}",
 "id": "{service}",
 "split": {{
  "allocations": {{
   "{version}": 1
  }}
 }}
}}
"""

GAE_GET_SERVICES = {
    "project4": [
        json.loads(
            APPENGINE_SERVICE_TEMPLATE.format(
                project="project4", service="default", version="1")),
    ],
}

# Fields: project, service, version
APPENGINE_VERSION_TEMPLATE = """
{{
 "name": "apps/{project}/services/{service}/versions/{version}",
 "id": "{version}",
 "instanceClass": "F1",
 "runtime": "python27",
 "threadsafe": true,
 "env": "standard",
 "servingStatus": "SERVING",
 "createdBy": "a_user@forseti.test",
 "createTime": "2017-09-11T22:48:32Z",
 "diskUsageBytes": "2036",
 "versionUrl": "https://{version}-dot-{project}.a.b.c"
}}
"""

GAE_GET_VERSIONS = {
    "project4": {"default": [
        json.loads(
            APPENGINE_VERSION_TEMPLATE.format(
                project="project4", service="default", version="1")),
    ]},
}

# Fields: project, service, version, instance
APPENGINE_INSTANCE_TEMPLATE = """
{{
 "name": "apps/{project}/services/{service}/versions/{version}/instances/{instance}",
 "id": "{instance}",
 "appEngineRelease": "1.9.54",
 "availability": "DYNAMIC",
 "startTime": "2017-09-11T22:49:03.485539Z",
 "requests": 3,
 "memoryUsage": "22802432"
}}
"""

GAE_GET_INSTANCES = {
    "project4": {"default": {"1": [
        json.loads(
            APPENGINE_INSTANCE_TEMPLATE.format(
                project="project4", service="default", version="1",
                instance="1")),
        json.loads(
            APPENGINE_INSTANCE_TEMPLATE.format(
                project="project4", service="default", version="1",
                instance="2")),
        json.loads(
            APPENGINE_INSTANCE_TEMPLATE.format(
                project="project4", service="default", version="1",
                instance="3")),
    ]}},
}

BQ_GET_DATASETS_FOR_PROJECTID = {
    PROJECT_ID_PREFIX + "3": [{
        "datasetReference": {
            "datasetId": "dataset1",
            "projectId": "project3"
        },
        "id": "project3:dataset1",
        "kind": "bigquery#dataset"
    }]
}

BQ_GET_DATASET_ACCESS = {
    PROJECT_ID_PREFIX + "3": {
        "dataset1": [{
            "role": "WRITER",
            "specialGroup": "projectWriters"
        }, {
            "role": "OWNER",
            "specialGroup": "projectOwners"
        }, {
            "role": "OWNER",
            "userByEmail": "a_user@forseti.test"
        }, {
            "role": "READER",
            "specialGroup": "projectReaders"
        }]
    }
}

CRM_GET_ORGANIZATION = {
    ORGANIZATION_ID: {
        "displayName": "forseti.test",
        "owner": {
            "directoryCustomerId": GSUITE_CUSTOMER_ID
        },
        "creationTime": "2015-09-09T19:34:18.591Z",
        "lifecycleState": "ACTIVE",
        "name": ORGANIZATION_ID
    }
}

# Fields: id, parent, name
CRM_FOLDER_TEMPLATE = """
{{
 "name": "folders/103{id}",
 "parent": "{parent}",
 "displayName": "{name}",
 "lifecycleState": "ACTIVE",
 "createTime": "2017-02-09T22:02:07.769Z"
}}
"""

CRM_GET_FOLDER = {
    "folders/" + FOLDER_ID_PREFIX + "1":
        json.loads(
            CRM_FOLDER_TEMPLATE.format(
                id=1, parent=ORGANIZATION_ID, name="Folder 1")),
    "folders/" + FOLDER_ID_PREFIX + "2":
        json.loads(
            CRM_FOLDER_TEMPLATE.format(
                id=2, parent=ORGANIZATION_ID, name="Folder 2")),
    "folders/" + FOLDER_ID_PREFIX + "3":
        json.loads(
            CRM_FOLDER_TEMPLATE.format(
                id=3, parent="folders/" + FOLDER_ID_PREFIX + "2",
                name="Folder 3")),
}

CRM_GET_FOLDERS = {
    ORGANIZATION_ID: [
        CRM_GET_FOLDER["folders/" + FOLDER_ID_PREFIX + "1"],
        CRM_GET_FOLDER["folders/" + FOLDER_ID_PREFIX + "2"]
    ],
    "folders/" + FOLDER_ID_PREFIX + "1": [],
    "folders/" + FOLDER_ID_PREFIX + "2": [
        CRM_GET_FOLDER["folders/" + FOLDER_ID_PREFIX + "3"]
    ],
    "folders/" + FOLDER_ID_PREFIX + "3": [],
}

# Fields: num, id, name, parent_type, parent_id
CRM_PROJECT_TEMPLATE = """
{{
 "projectNumber": "104{num}",
 "projectId": "{id}",
 "lifecycleState": "ACTIVE",
 "name": "{name}",
 "createTime": "2017-07-12T17:50:40.895Z",
 "parent": {{
  "type": "{parent_type}",
  "id": "{parent_id}"
 }}
}}
"""

CRM_GET_PROJECT = {
    PROJECT_ID_PREFIX + "1":
        json.loads(
            CRM_PROJECT_TEMPLATE.format(
                num=1,
                id="project1",
                name="Project 1",
                parent_type="organization",
                parent_id="111222333")),
    PROJECT_ID_PREFIX + "2":
        json.loads(
            CRM_PROJECT_TEMPLATE.format(
                num=2,
                id="project2",
                name="Project 2",
                parent_type="organization",
                parent_id="111222333")),
    PROJECT_ID_PREFIX + "3":
        json.loads(
            CRM_PROJECT_TEMPLATE.format(
                num=3,
                id="project3",
                name="Project 3",
                parent_type="folder",
                parent_id=FOLDER_ID_PREFIX + "1")),
    PROJECT_ID_PREFIX + "4":
        json.loads(
            CRM_PROJECT_TEMPLATE.format(
                num=4,
                id="project4",
                name="Project 4",
                parent_type="folder",
                parent_id=FOLDER_ID_PREFIX + "3")),
}

CRM_GET_PROJECTS = {
    "organization": {
        "111222333": [{
            "projects": [
                CRM_GET_PROJECT[PROJECT_ID_PREFIX + "1"],
                CRM_GET_PROJECT[PROJECT_ID_PREFIX + "2"]
            ]
        }]
    },
    "folder": {
        FOLDER_ID_PREFIX + "1": [{
            "projects": [CRM_GET_PROJECT[PROJECT_ID_PREFIX + "3"]]
        }],
        FOLDER_ID_PREFIX + "2": [],
        FOLDER_ID_PREFIX + "3": [{
            # Make sure duplicate api response doesn't block data model from building.
            "projects": [CRM_GET_PROJECT[PROJECT_ID_PREFIX + "4"],
                         CRM_GET_PROJECT[PROJECT_ID_PREFIX + "4"]]
        }]
    }
}

# Fields: id
CRM_PROJECT_IAM_POLICY_TEMPLATE = """
{{
 "bindings": [
  {{
   "role": "roles/editor",
   "members": [
    "serviceAccount:{id}@cloudservices.gserviceaccount.com",
    "serviceAccount:{id}-compute@developer.gserviceaccount.com"
   ]
  }},
  {{
   "role": "roles/owner",
   "members": [
    "group:c_grp@forseti.test",
    "user:a_user@forseti.test"
   ]
  }}
 ],
 "auditConfigs": [
  {{
   "auditLogConfigs": [
    {{
     "logType": "ADMIN_READ"
    }},
    {{
     "logType": "DATA_WRITE"
    }},
    {{
     "logType": "DATA_READ"
    }}
   ],
   "service": "allServices"
  }},
  {{
   "auditLogConfigs": [
    {{
     "exemptedMembers": [
      "user:gcp-reader-12345@p1234.iam.gserviceaccount.com"
     ],
     "logType": "ADMIN_READ"
    }}
   ],
   "service": "cloudsql.googleapis.com"
  }}
 ]
}}
"""

CRM_PROJECT_IAM_POLICY_MEMBER_MULTI_ROLES = """
{{
 "bindings": [
  {{
   "role": "roles/editor",
   "members": [
    "serviceAccount:{id}@cloudservices.gserviceaccount.com",
    "serviceAccount:{id}-compute@developer.gserviceaccount.com"
   ]
  }},
  {{
   "role": "roles/owner",
   "members": [
    "group:c_grp@forseti.test",
    "user:a_user@forseti.test"
   ]
  }},
  {{
   "role": "roles/appengine.codeViewer",
   "members": [
    "user:abc_user@forseti.test"
   ]
  }},
  {{
   "role": "roles/appengine.appViewer",
   "members": [
    "user:abc_user@forseti.test"
   ]
  }}
 ]
}}
"""

CRM_PROJECT_IAM_POLICY_DUP_MEMBER = """
{{
 "bindings": [
  {{
   "role": "roles/editor",
   "members": [
    "serviceAccount:{id}@cloudservices.gserviceaccount.com",
    "serviceAccount:{id}-compute@developer.gserviceaccount.com",
    "serviceAccount:{id}@cloudservices.gserviceaccount.com"
   ]
  }},
  {{
   "role": "roles/owner",
   "members": [
    "group:c_grp@forseti.test",
    "user:a_user@forseti.test"
   ]
  }}
 ]
}}
"""

CRM_FOLDER_IAM_POLICY = """
{
 "bindings": [
  {
   "role": "roles/resourcemanager.folderAdmin",
   "members": [
    "user:a_user@forseti.test"
   ]
  }
 ]
}
"""

CRM_ORG_IAM_POLICY = """
{
 "bindings": [
  {
   "role": "roles/resourcemanager.organizationAdmin",
   "members": [
    "user:a_user@forseti.test"
   ]
  }
 ],
 "auditConfigs": [
  {
   "auditLogConfigs": [
    {
     "logType": "ADMIN_READ"
    }
   ],
   "service": "allServices"
  }
 ]
}
"""

CRM_GET_IAM_POLICIES = {
    ORGANIZATION_ID: json.loads(CRM_ORG_IAM_POLICY),
    "folders/" + FOLDER_ID_PREFIX + "1": json.loads(CRM_FOLDER_IAM_POLICY),
    "folders/" + FOLDER_ID_PREFIX + "2": json.loads(CRM_FOLDER_IAM_POLICY),
    "folders/" + FOLDER_ID_PREFIX + "3": json.loads(CRM_FOLDER_IAM_POLICY),
    PROJECT_ID_PREFIX + "1": json.loads(CRM_PROJECT_IAM_POLICY_TEMPLATE.format(id=1)),
    PROJECT_ID_PREFIX + "2": json.loads(CRM_PROJECT_IAM_POLICY_TEMPLATE.format(id=2)),
    PROJECT_ID_PREFIX + "3": json.loads(CRM_PROJECT_IAM_POLICY_MEMBER_MULTI_ROLES.format(id=3)),
    PROJECT_ID_PREFIX + "4": json.loads(CRM_PROJECT_IAM_POLICY_DUP_MEMBER.format(id=4)),
}

CRM_ORG_ORG_POLICIES = """
[
  {
    "constraint": "constraints/compute.disableSerialPortAccess",
    "booleanPolicy": {
     "enforced": true
    }
  },
  {
    "constraint": "constraints/compute.storageResourceUseRestrictions",
    "list_policy": {
      "all_values": "ALLOW"
    }
  }
]
"""

CRM_FOLDER_ORG_POLICIES = """
[
  {
    "constraint": "constraints/storage.bucketPolicyOnly",
    "boolean_policy": {
      "enforced": true
    }
  }
]
"""


CRM_PROJECT_ORG_POLICIES = """
[
  {
    "constraint": "constraints/compute.trustedImageProjects",
    "list_policy": {
      "allowed_values": [
        "is:projects/my-good-images",
        "is:projects/my-other-images",
        "is:projects/trusted-cloud-images"
      ]
    }
  }
]
"""

CRM_GET_ORG_POLICIES = {
    ORGANIZATION_ID: json.loads(CRM_ORG_ORG_POLICIES),
    "folders/" + FOLDER_ID_PREFIX + "1": json.loads(CRM_FOLDER_ORG_POLICIES),
    "folders/" + FOLDER_ID_PREFIX + "2": {},
    "folders/" + FOLDER_ID_PREFIX + "3": {},
    PROJECT_ID_PREFIX + "1": json.loads(CRM_PROJECT_ORG_POLICIES),
    PROJECT_ID_PREFIX + "2": json.loads(CRM_PROJECT_ORG_POLICIES),
    PROJECT_ID_PREFIX + "3": {},
    PROJECT_ID_PREFIX + "4": {},
}

CRM_GET_PROJECT_LIENS = {
    PROJECT_ID_PREFIX + "1": [{
        "name": "liens/" + LIEN_ID_PREFIX,
        "parent": "projects/project1",
        "restrictions": [
            "resourcemanager.projects.delete"
        ],
        "origin": "testing",
        "createTime": "2018-09-05T14:45:46.534Z",
    }],
}

GCP_PERMISSION_DENIED_TEMPLATE = """
{{
 "error": {{
  "errors": [
   {{
    "domain": "global",
    "reason": "forbidden",
    "message": "The caller does not have permission on {id}.",
   }}
  ],
  "code": 403,
  "message": "The caller does not have permission on {id}."
 }}
}}
"""

# Fields: name, project, ip
SQL_INSTANCE_TEMPLATE = """
{{
 "kind": "sql#instance",
 "name": "{name}",
 "connectionName": "{project}:us-west1:{name}",
 "project": "{project}",
 "state": "RUNNABLE",
 "backendType": "SECOND_GEN",
 "databaseVersion": "MYSQL_5_7",
 "region": "us-west1",
 "settings": {{
  "kind": "sql#settings",
  "settingsVersion": "13",
  "authorizedGaeApplications": [
  ],
  "tier": "db-n1-standard-1",
  "backupConfiguration": {{
   "kind": "sql#backupConfiguration",
   "startTime": "09:00",
   "enabled": true,
   "binaryLogEnabled": true
  }},
  "pricingPlan": "PER_USE",
  "replicationType": "SYNCHRONOUS",
  "activationPolicy": "ALWAYS",
  "ipConfiguration": {{
   "ipv4Enabled": true,
   "authorizedNetworks": [
   ]
  }},
  "locationPreference": {{
   "kind": "sql#locationPreference",
   "zone": "us-west1-a"
  }},
  "dataDiskSizeGb": "10",
  "dataDiskType": "PD_SSD",
  "maintenanceWindow": {{
   "kind": "sql#maintenanceWindow",
   "hour": 0,
   "day": 0
  }},
  "storageAutoResize": true,
  "storageAutoResizeLimit": "0"
 }},
 "serverCaCert": {{
  "kind": "sql#sslCert",
  "instance": "{name}",
  "sha1Fingerprint": "1234567890",
  "commonName": "C=US,O=Test",
  "certSerialNumber": "0",
  "cert": "-----BEGIN CERTIFICATE----------END CERTIFICATE-----",
  "createTime": "2017-11-22T17:59:22.085Z",
  "expirationTime": "2019-11-22T18:00:22.085Z"
 }},
 "ipAddresses": [
  {{
   "ipAddress": "{ip}",
   "type": "PRIMARY"
  }}
 ],
 "instanceType": "CLOUD_SQL_INSTANCE",
 "gceZone": "us-west1-a"
}}
"""

SQL_GET_INSTANCES = {
    PROJECT_ID_PREFIX + "2": [
        json.loads(
            SQL_INSTANCE_TEMPLATE.format(
                name="forseti", project="project2", ip="192.168.2.2")),
    ]
}

GCE_API_NOT_ENABLED_TEMPLATE = """
{{
 "error": {{
  "errors": [
   {{
    "domain": "usageLimits",
    "reason": "accessNotConfigured",
    "message": "Access Not Configured. Compute Engine API has not been used in project {id} before or it is disabled. Enable it by visiting https://console.developers.google.com/apis/api/compute.googleapis.com/overview?project={id} then retry. If you enabled this API recently, wait a few minutes for the action to propagate to our systems and retry.",
    "extendedHelp": "https://console.developers.google.com/apis/api/compute.googleapis.com/overview?project={id}"
   }}
  ],
  "code": 403,
  "message": "Access Not Configured. Compute Engine API has not been used in project {id} before or it is disabled. Enable it by visiting https://console.developers.google.com/apis/api/compute.googleapis.com/overview?project={id} then retry. If you enabled this API recently, wait a few minutes for the action to propagate to our systems and retry."
 }}
}}
"""

# Fields: num, id, projnum
GCE_PROJECT_TEMPLATE = """
{{
 "kind": "compute#project",
 "id": "105{num}",
 "creationTimestamp": "2016-02-25T14:01:23.140-08:00",
 "name": "{id}",
 "commonInstanceMetadata": {{
  "kind": "compute#metadata",
  "fingerprint": "ABC",
  "items": [
   {{
    "key": "some-key",
    "value": "some-value"
   }}
  ]
 }},
 "quotas": [
  {{
   "metric": "SNAPSHOTS",
   "limit": 1000.0,
   "usage": 0.0
  }},
  {{
   "metric": "NETWORKS",
   "limit": 5.0,
   "usage": 1.0
  }}
 ],
 "selfLink": "https://www.googleapis.com/compute/v1/projects/{id}",
 "defaultServiceAccount": "{projnum}-compute@developer.gserviceaccount.com",
 "xpnProjectStatus": "UNSPECIFIED_XPN_PROJECT_STATUS"
}}
"""

GCE_GET_PROJECT = {
    PROJECT_ID_PREFIX + "1":
        json.loads(
            GCE_PROJECT_TEMPLATE.format(
                num=1, id="project1", projnum=PROJECT_ID_PREFIX + "1")),
    PROJECT_ID_PREFIX + "2":
        json.loads(
            GCE_PROJECT_TEMPLATE.format(
                num=2, id="project2", projnum=PROJECT_ID_PREFIX + "2")),
    PROJECT_ID_PREFIX + "3":
        json.loads(
            GCE_PROJECT_TEMPLATE.format(
                num=3, id="project3", projnum=PROJECT_ID_PREFIX + "3")),
}

# Fields: id, name, project, num, ip, external_ip, network, template,
#     groupmanager
GCE_INSTANCE_TEMPLATE_IAP = """
{{
 "kind": "compute#instance",
 "id": "106{id}",
 "creationTimestamp": "2017-05-26T22:08:11.094-07:00",
 "name": "{name}",
 "tags": {{
  "items": [
   "iap-tag"
  ],
  "fingerprint": "gilEhx3hEXk="
 }},
 "machineType": "https://www.googleapis.com/compute/v1/projects/{project}/zones/us-central1-c/machineTypes/f1-micro",
 "status": "RUNNING",
 "zone": "https://www.googleapis.com/compute/v1/projects/{project}/zones/us-central1-c",
 "canIpForward": false,
 "networkInterfaces": [
  {{
   "kind": "compute#networkInterface",
   "network": "https://www.googleapis.com/compute/v1/projects/{project}/global/networks/{network}",
   "subnetwork": "https://www.googleapis.com/compute/v1/projects/{project}/regions/us-central1/subnetworks/{network}",
   "networkIP": "{ip}",
   "name": "nic0",
   "accessConfigs": [
    {{
     "kind": "compute#accessConfig",
     "type": "ONE_TO_ONE_NAT",
     "name": "External NAT",
     "natIP": "{external_ip}"
    }}
   ]
  }}
 ],
 "disks": [
  {{
   "kind": "compute#attachedDisk",
   "type": "PERSISTENT",
   "mode": "READ_WRITE",
   "source": "https://www.googleapis.com/compute/v1/projects/{project}/zones/us-central1-c/disks/{name}",
   "deviceName": "{template}",
   "index": 0,
   "boot": true,
   "autoDelete": true,
   "licenses": [
    "https://www.googleapis.com/compute/v1/projects/debian-cloud/global/licenses/debian-8-jessie"
   ],
   "interface": "SCSI"
  }}
 ],
 "metadata": {{
 "kind": "compute#metadata",
 "fingerprint": "3MpZMMvDTyo=",
 "items": [
  {{
   "key": "instance-template",
   "value": "projects/{num}/global/instanceTemplates/{template}"
  }},
  {{
   "key": "created-by",
   "value": "projects/{num}/zones/us-central1-c/instanceGroupManagers/{groupmanager}"
  }}
 ]
 }},
 "serviceAccounts": [
  {{
   "email": "{num}-compute@developer.gserviceaccount.com",
   "scopes": [
    "https://www.googleapis.com/auth/devstorage.read_only",
    "https://www.googleapis.com/auth/logging.write",
    "https://www.googleapis.com/auth/monitoring.write",
    "https://www.googleapis.com/auth/servicecontrol",
    "https://www.googleapis.com/auth/service.management.readonly",
    "https://www.googleapis.com/auth/trace.append"
   ]
  }}
 ],
 "selfLink": "https://www.googleapis.com/compute/v1/projects/{project}/zones/us-central1-c/instances/{name}",
 "scheduling": {{
  "onHostMaintenance": "MIGRATE",
  "automaticRestart": true,
  "preemptible": false
 }},
 "cpuPlatform": "Intel Haswell"
}}
"""

# Fields: id, name, project, num, ip, external_ip, network
GCE_INSTANCE_TEMPLATE_STANDARD = """
{{
 "kind": "compute#instance",
 "id": "106{id}",
 "creationTimestamp": "2017-11-22T09:47:37.688-08:00",
 "name": "{name}",
 "description": "",
 "tags": {{
  "fingerprint": "42WmSpB8rSM="
 }},
 "machineType": "https://www.googleapis.com/compute/v1/projects/{project}/zones/us-west1-a/machineTypes/n1-standard-2",
 "status": "RUNNING",
 "zone": "https://www.googleapis.com/compute/v1/projects/{project}/zones/us-west1-a",
 "canIpForward": false,
 "networkInterfaces": [
  {{
   "kind": "compute#networkInterface",
   "network": "https://www.googleapis.com/compute/v1/projects/{project}/global/networks/{network}",
   "subnetwork": "https://www.googleapis.com/compute/v1/projects/{project}/regions/us-west1/subnetworks/{network}",
   "networkIP": "{ip}",
   "name": "nic0",
   "accessConfigs": [
    {{
     "kind": "compute#accessConfig",
     "type": "ONE_TO_ONE_NAT",
     "name": "External NAT",
     "natIP": "{external_ip}"
    }}
   ],
   "fingerprint": "Z9b15gLF1tc="
  }}
 ],
 "disks": [
  {{
   "kind": "compute#attachedDisk",
   "type": "PERSISTENT",
   "mode": "READ_WRITE",
   "source": "https://www.googleapis.com/compute/v1/projects/{project}/zones/us-west1-a/disks/{name}",
   "deviceName": "{name}",
   "index": 0,
   "boot": true,
   "autoDelete": true,
   "licenses": [
    "https://www.googleapis.com/compute/v1/projects/ubuntu-os-cloud/global/licenses/ubuntu-1604-xenial"
   ],
   "interface": "SCSI"
  }}
 ],
 "metadata": {{
  "kind": "compute#metadata",
  "fingerprint": "n9X2Zj3rDe0="
 }},
 "serviceAccounts": [
  {{
   "email": "{num}-compute@developer.gserviceaccount.com",
   "scopes": [
    "https://www.googleapis.com/auth/cloud-platform"
   ]
  }}
 ],
 "selfLink": "https://www.googleapis.com/compute/v1/projects/{project}/zones/us-west1-a/instances/{name}",
 "scheduling": {{
  "onHostMaintenance": "MIGRATE",
  "automaticRestart": true,
  "preemptible": false
 }},
 "cpuPlatform": "Intel Broadwell",
 "labelFingerprint": "42WmSpB8rSM=",
 "startRestricted": false,
 "deletionProtection": false
}}
"""

GCE_GET_INSTANCES = {
    PROJECT_ID_PREFIX + "1": [
        json.loads(
            GCE_INSTANCE_TEMPLATE_IAP.format(
                id=1,
                name="iap_instance1",
                project="project1",
                num=PROJECT_ID_PREFIX + "1",
                ip="10.138.0.2",
                external_ip="192.168.1.2",
                network="default",
                template="instance_template1",
                groupmanager="group_manager1")),
        json.loads(
            GCE_INSTANCE_TEMPLATE_IAP.format(
                id=2,
                name="iap_instance2",
                project="project1",
                num=PROJECT_ID_PREFIX + "1",
                ip="10.138.0.3",
                external_ip="192.168.1.3",
                network="default",
                template="instance_template1",
                groupmanager="group_manager1")),
        json.loads(
            GCE_INSTANCE_TEMPLATE_IAP.format(
                id=3,
                name="iap_instance3",
                project="project1",
                num=PROJECT_ID_PREFIX + "1",
                ip="10.138.0.4",
                external_ip="192.168.1.4",
                network="default",
                template="instance_template1",
                groupmanager="group_manager1")),
    ],
    PROJECT_ID_PREFIX + "2": [
        json.loads(
            GCE_INSTANCE_TEMPLATE_STANDARD.format(
                id=4,
                name="instance3",
                project="project2",
                num=PROJECT_ID_PREFIX + "2",
                ip="10.138.0.2",
                external_ip="192.168.1.5",
                network="default")),
    ]
}

# Fields: network, id, project
GCE_FIREWALL_TEMPLATE_DEFAULT = """
[
  {{
   "kind": "compute#firewall",
   "id": "107{id}1",
   "creationTimestamp": "2017-05-04T16:23:00.568-07:00",
   "network": "https://www.googleapis.com/compute/beta/projects/{project}/global/networks/{network}",
   "priority": 1000,
   "sourceRanges": ["0.0.0.0/0"],
   "description": "Allow ICMP from anywhere",
   "allowed": [
    {{
     "IPProtocol": "icmp"
    }}
   ],
   "name": "{network}-allow-icmp",
   "direction": "INGRESS",
   "selfLink": "https://www.googleapis.com/compute/beta/projects/{project}/global/firewalls/{network}-allow-icmp"
  }},
  {{
   "kind": "compute#firewall",
   "id": "107{id}2",
   "creationTimestamp": "2017-05-04T16:23:00.568-07:00",
   "network": "https://www.googleapis.com/compute/beta/projects/{project}/global/networks/{network}",
   "priority": 1000,
   "sourceRanges": ["0.0.0.0/0"],
   "description": "Allow RDP from anywhere",
   "allowed": [
    {{
     "IPProtocol": "tcp",
     "ports": ["3389"]
    }}
   ],
   "name": "{network}-allow-rdp",
   "direction": "INGRESS",
   "selfLink": "https://www.googleapis.com/compute/beta/projects/{project}/global/firewalls/{network}-allow-rdp"
  }},
  {{
   "kind": "compute#firewall",
   "id": "107{id}3",
   "creationTimestamp": "2017-05-04T16:23:00.568-07:00",
   "network": "https://www.googleapis.com/compute/beta/projects/{project}/global/networks/{network}",
   "priority": 1000,
   "sourceRanges": ["0.0.0.0/0"],
   "description": "Allow SSH from anywhere",
   "allowed": [
    {{
     "IPProtocol": "tcp",
     "ports": ["22"]
    }}
   ],
   "name": "{network}-allow-ssh",
   "direction": "INGRESS",
   "selfLink": "https://www.googleapis.com/compute/beta/projects/{project}/global/firewalls/{network}-allow-ssh"
  }},
  {{
   "kind": "compute#firewall",
   "id": "107{id}4",
   "creationTimestamp": "2017-05-04T16:23:00.568-07:00",
   "network": "https://www.googleapis.com/compute/beta/projects/{project}/global/networks/{network}",
   "priority": 1000,
   "sourceRanges": ["10.0.0.0/8"],
   "description": "Allow internal traffic on the {network} network.",
   "allowed": [
    {{
     "IPProtocol": "udp",
     "ports": ["1-65535"]
    }},
    {{
     "IPProtocol": "tcp",
     "ports": ["1-65535"]
    }},
    {{
     "IPProtocol": "icmp"
    }}
   ],
   "name": "{network}-allow-internal",
   "direction": "INGRESS",
   "selfLink": "https://www.googleapis.com/compute/beta/projects/{project}/global/firewalls/{network}-allow-internal"
  }}
]
"""

# Fields: network, id, project
GCE_FIREWALL_TEMPLATE_IAP = """
[
  {{
   "kind": "compute#firewall",
   "id": "107{id}1",
   "creationTimestamp": "2017-05-04T16:23:00.568-07:00",
   "network": "https://www.googleapis.com/compute/beta/projects/{project}/global/networks/{network}",
   "priority": 1000,
   "sourceRanges": ["130.211.0.0/22", "35.191.0.0/16"],
   "description": "Allow HTTP and HTTPS from LB",
   "allowed": [
    {{
     "IPProtocol": "tcp",
     "ports": ["80", "443"]
    }}
   ],
   "targetTags": ["iap-tag"],
   "name": "{network}-allow-https-lb",
   "direction": "INGRESS",
   "selfLink": "https://www.googleapis.com/compute/beta/projects/{project}/global/firewalls/{network}-allow-https-lb"
  }},
  {{
   "kind": "compute#firewall",
   "id": "107{id}2",
   "creationTimestamp": "2017-05-04T16:23:00.568-07:00",
   "network": "https://www.googleapis.com/compute/beta/projects/{project}/global/networks/{network}",
   "priority": 1000,
   "sourceRanges": ["0.0.0.0/0"],
   "description": "Allow SSH from anywhere",
   "allowed": [
    {{
     "IPProtocol": "tcp",
     "ports": ["22"]
    }}
   ],
   "name": "{network}-allow-ssh",
   "direction": "INGRESS",
   "selfLink": "https://www.googleapis.com/compute/beta/projects/{project}/global/firewalls/{network}-allow-ssh"
  }},
  {{
   "kind": "compute#firewall",
   "id": "107{id}3",
   "creationTimestamp": "2017-05-04T16:23:00.568-07:00",
   "network": "https://www.googleapis.com/compute/beta/projects/{project}/global/networks/{network}",
   "priority": 1000,
   "sourceRanges": ["10.0.0.0/8"],
   "description": "Allow SSH and ICMP between instances on {network} network.",
   "allowed": [
    {{
     "IPProtocol": "tcp",
     "ports": ["22"]
    }},
    {{
     "IPProtocol": "icmp"
    }}
   ],
   "name": "{network}-allow-internal",
   "direction": "INGRESS",
   "selfLink": "https://www.googleapis.com/compute/beta/projects/{project}/global/firewalls/{network}-allow-internal"
  }}
]
"""

GCE_GET_FIREWALLS = {
    PROJECT_ID_PREFIX + "1":
        json.loads(
            GCE_FIREWALL_TEMPLATE_IAP.format(
                id=1, project="project1", network="default")),
    PROJECT_ID_PREFIX + "2":
        json.loads(
            GCE_FIREWALL_TEMPLATE_DEFAULT.format(
                id=2, project="project2", network="default")),
}

# Fields: id, project, zone, name
GCE_DISKS_TEMPLATE = """
{{
 "kind": "compute#disk",
 "id": "118{id}",
 "creationTimestamp": "2017-08-07T10:18:45.802-07:00",
 "name": "instance-1",
 "sizeGb": "10",
 "zone": "https://www.googleapis.com/compute/v1/projects/{project}/zones/{zone}",
 "status": "READY",
 "selfLink": "https://www.googleapis.com/compute/v1/projects/{project}/zones/{zone}/disks/{name}",
 "sourceImage": "https://www.googleapis.com/compute/v1/projects/debian-cloud/global/images/debian-9-stretch-v20170717",
 "sourceImageId": "4214972497302618486",
 "type": "https://www.googleapis.com/compute/v1/projects/{project}/zones/{zone}/diskTypes/pd-standard",
 "licenses": [
  "https://www.googleapis.com/compute/v1/projects/debian-cloud/global/licenses/debian-9-stretch"
 ],
 "lastAttachTimestamp": "2017-08-07T10:18:45.806-07:00",
 "users": [
  "https://www.googleapis.com/compute/v1/projects/{project}/zones/{zone}/instances/{name}"
 ],
 "labelFingerprint": "42WmSpB8rSM="
}}
"""

GCE_GET_DISKS = {
    PROJECT_ID_PREFIX + "1": [
        json.loads(
            GCE_DISKS_TEMPLATE.format(
                id=1,
                name="iap_instance1",
                project="project1",
                zone="us-central1-c")),
        json.loads(
            GCE_DISKS_TEMPLATE.format(
                id=2,
                name="iap_instance2",
                project="project1",
                zone="us-central1-c")),
        json.loads(
            GCE_DISKS_TEMPLATE.format(
                id=3,
                name="iap_instance3",
                project="project1",
                zone="us-central1-c")),
    ],
    PROJECT_ID_PREFIX + "2": [
        json.loads(
            GCE_DISKS_TEMPLATE.format(
                id=4,
                name="instance3",
                project="project2",
                zone="us-west1-a")),
    ]
}

# Fields: id, project
GCE_IMAGES_TEMPLATE = """
[
{{
 "kind": "compute#image",
 "id": "117{id}1",
 "creationTimestamp": "2017-11-15T21:59:58.627-08:00",
 "name": "centos-6-custom-v20171116",
 "description": "Custom CentOS 6 built on 20171116",
 "sourceType": "RAW",
 "deprecated": {{
  "state": "DEPRECATED",
  "replacement": "https://www.googleapis.com/compute/v1/projects/{project}/global/images/centos-6-custom-v20171208"
 }},
 "status": "READY",
 "archiveSizeBytes": "688350464",
 "diskSizeGb": "10",
 "sourceDisk": "https://www.googleapis.com/compute/v1/projects/{project}/zones/us-central1-b/disks/disk-install-centos-6-custom-dz0wt",
 "sourceDiskId": "2345",
 "licenses": [
  "https://www.googleapis.com/compute/v1/projects/centos-cloud/global/licenses/centos-6"
 ],
 "family": "centos-6-custom",
 "selfLink": "https://www.googleapis.com/compute/v1/projects/{project}/global/images/centos-6-custom-v20171116",
 "labelFingerprint": "42WmSpB8rSM=",
 "guestOsFeatures": [
  {{
   "type": "VIRTIO_SCSI_MULTIQUEUE"
  }}
 ]
}},
{{
 "kind": "compute#image",
 "id": "117{id}2",
 "creationTimestamp": "2017-12-07T16:19:13.482-08:00",
 "name": "centos-6-custom-v20171208",
 "description": "Custom CentOS 6 built on 20171208",
 "sourceType": "RAW",
 "status": "READY",
 "archiveSizeBytes": "788880064",
 "diskSizeGb": "10",
 "sourceDisk": "https://www.googleapis.com/compute/v1/projects/{project}/zones/us-central1-b/disks/disk-install-centos-6-custom-62bzs",
 "sourceDiskId": "5678",
 "licenses": [
  "https://www.googleapis.com/compute/v1/projects/centos-cloud/global/licenses/centos-6"
 ],
 "family": "centos-6-custom",
 "selfLink": "https://www.googleapis.com/compute/v1/projects/{project}/global/images/centos-6-custom-v20171208",
 "labelFingerprint": "42WmSpB8rSM=",
 "guestOsFeatures": [
  {{
   "type": "VIRTIO_SCSI_MULTIQUEUE"
  }}
 ]
}}
]
"""

GCE_GET_IMAGES = {
    PROJECT_ID_PREFIX + "2":
        json.loads(
            GCE_IMAGES_TEMPLATE.format(
                id=1, project="project2")),
}

# Fields: project, instance1, instance2, instance3
GCE_INSTANCE_GROUP_INSTANCES_TEMPLATE = """
[
  "https://www.googleapis.com/compute/v1/projects/{project}/zones/us-central1-c/instances/{instance1}",
  "https://www.googleapis.com/compute/v1/projects/{project}/zones/us-central1-c/instances/{instance2}",
  "https://www.googleapis.com/compute/v1/projects/{project}/zones/us-central1-c/instances/{instance3}"
]
"""

GCE_GET_INSTANCE_GROUP_INSTANCES = {
    PROJECT_ID_PREFIX + "1": {
        "bs-1-ig-1": json.loads(
            GCE_INSTANCE_GROUP_INSTANCES_TEMPLATE.format(
                project="project1",
                instance1="iap_instance1",
                instance2="iap_instance2",
                instance3="iap_instance3")),
        "gke-cluster-1-default-pool-12345678-grp": json.loads(
            GCE_INSTANCE_GROUP_INSTANCES_TEMPLATE.format(
                project="project1",
                instance1="ke_instance1",
                instance2="ke_instance2",
                instance3="ke_instance3")),
    }
}

# Fields: id, name, project, network
GCE_INSTANCE_GROUPS_TEMPLATE = """
{{
 "kind": "compute#instanceGroup",
 "id": "108{id}",
 "creationTimestamp": "2017-08-24T11:10:06.771-07:00",
 "name": "{name}",
 "description": "This instance group is controlled by Regional Instance Group Manager '{name}'. To modify instances in this group, use the Regional Instance Group Manager API: https://cloud.google.com/compute/docs/reference/latest/instanceGroupManagers",
 "network": "https://www.googleapis.com/compute/v1/projects/{project}/global/networks/{network}",
 "fingerprint": "42WmSpB8rSM=",
 "selfLink": "https://www.googleapis.com/compute/v1/projects/{project}/regions/us-central1/instanceGroups/{name}",
 "size": 3,
 "region": "https://www.googleapis.com/compute/v1/projects/{project}/regions/us-central1",
 "subnetwork": "https://www.googleapis.com/compute/v1/projects/{project}/regions/us-central1/subnetworks/{network}"
}}
"""

GCE_GET_INSTANCE_GROUPS = {
    PROJECT_ID_PREFIX + "1": [
        json.loads(
            GCE_INSTANCE_GROUPS_TEMPLATE.format(
                id=1,
                name="bs-1-ig-1",
                project="project1",
                network="default")),
        json.loads(
            GCE_INSTANCE_GROUPS_TEMPLATE.format(
                id=2,
                name="gke-cluster-1-default-pool-12345678-grp",
                project="project1",
                network="default")),
    ]
}

# Fields: id, name, project, ig_name, hc_name
GCE_BACKEND_SERVICES_TEMPLATE_IAP = """
{{
  "kind": "compute#backendService",
  "id": "109{id}",
  "creationTimestamp": "2017-05-12T11:14:18.559-07:00",
  "name": "{name}",
  "description": "",
  "selfLink": "https://www.googleapis.com/compute/beta/projects/{project}/global/backendServices/{name}",
  "backends": [
      {{
          "description": "",
          "group": "https://www.googleapis.com/compute/beta/projects/{project}/zones/us-central1-c/instanceGroups/{ig_name}",
          "balancingMode": "UTILIZATION",
          "maxUtilization": 0.8,
          "capacityScaler": 1.0
      }}
  ],
  "healthChecks": [
      "https://www.googleapis.com/compute/beta/projects/{project}/global/healthChecks/{hc_name}"
  ],
  "timeoutSec": 30,
  "port": 80,
  "protocol": "HTTP",
  "portName": "http",
  "enableCDN": false,
  "sessionAffinity": "NONE",
  "affinityCookieTtlSec": 0,
  "loadBalancingScheme": "EXTERNAL",
  "connectionDraining": {{
      "drainingTimeoutSec": 300
  }},
  "iap": {{
      "enabled": true,
      "oauth2ClientId": "foo",
      "oauth2ClientSecretSha256": "bar"
  }}
}}
"""

GCE_GET_BACKEND_SERVICES = {
    PROJECT_ID_PREFIX + "1": [
        json.loads(
            GCE_BACKEND_SERVICES_TEMPLATE_IAP.format(
                id=1,
                name="bs-1",
                project="project1",
                ig_name="bs-1-ig-1",
                hc_name="bs-1-hc")),
    ]
}

# Fields: id, name, project, ip, target
FORWARDING_RULES_TEMPLATE = """
{{
  "kind": "compute#forwardingRule",
  "description": "",
  "IPAddress": "{ip}",
  "region": "https://www.googleapis.com/compute/v1/projects/{project}/regions/us-central1",
  "loadBalancingScheme": "EXTERNAL",
  "target": "https://www.googleapis.com/compute/v1/projects/{project}/regions/us-central1/{target}",
  "portRange": "80-80",
  "IPProtocol": "TCP",
  "creationTimestamp": "2017-05-05T12:00:01.000-07:00",
  "id": "111{id}",
  "selfLink": "https://www.googleapis.com/compute/v1/projects/{project}/regions/us-central1/forwardingRules/{name}",
  "name": "{name}"
}}
"""

GCE_GET_FORWARDING_RULES = {
    PROJECT_ID_PREFIX + "1": [
        json.loads(
            FORWARDING_RULES_TEMPLATE.format(
                id=1,
                name="lb-1",
                project="project1",
                ip="172.16.1.2",
                target="targetHttpProxies/lb-1-target-proxy")),
    ]
}

# Fields: id, name, project, template
INSTANCE_GROUP_MANAGER_TEMPLATE = """
{{
 "kind": "compute#instanceGroupManager",
 "id": "112{id}",
 "creationTimestamp": "2017-08-24T11:10:06.770-07:00",
 "name": "{name}",
 "region": "https://www.googleapis.com/compute/v1/projects/{project}/regions/us-central1",
 "instanceTemplate": "https://www.googleapis.com/compute/v1/projects/{project}/global/instanceTemplates/{template}",
 "instanceGroup": "https://www.googleapis.com/compute/v1/projects/{project}/regions/us-central1/instanceGroups/{name}",
 "baseInstanceName": "{name}",
 "currentActions": {{
  "none": 3,
  "creating": 0,
  "creatingWithoutRetries": 0,
  "recreating": 0,
  "deleting": 0,
  "abandoning": 0,
  "restarting": 0,
  "refreshing": 0
 }},
 "targetSize": 3,
 "selfLink": "https://www.googleapis.com/compute/v1/projects/{project}/regions/us-central1/instanceGroupManagers/{name}"
}}
"""

# Fields: id, name, project, template, zone
KE_INSTANCE_GROUP_MANAGER_TEMPLATE = """
{{
 "kind": "compute#instanceGroupManager",
 "id": "112{id}",
 "creationTimestamp": "2017-10-24T12:36:42.373-07:00",
 "name": "{name}",
 "zone": "https://www.googleapis.com/compute/v1/projects/{project}/zones/{zone}",
 "instanceTemplate": "https://www.googleapis.com/compute/v1/projects/{project}/global/instanceTemplates/{template}",
 "instanceGroup": "https://www.googleapis.com/compute/v1/projects/{project}/zones/{zone}/instanceGroups/{name}",
 "baseInstanceName": "{template}",
 "fingerprint": "Y81gWm4KRRY=",
 "currentActions": {{
  "none": 3,
  "creating": 0,
  "creatingWithoutRetries": 0,
  "recreating": 0,
  "deleting": 0,
  "abandoning": 0,
  "restarting": 0,
  "refreshing": 0
 }},
 "targetSize": 3,
 "selfLink": "https://www.googleapis.com/compute/v1/projects/{project}/zones/{zone}/instanceGroupManagers/{name}"
}}
"""

GCE_GET_INSTANCE_GROUP_MANAGERS = {
    PROJECT_ID_PREFIX + "1": [
        json.loads(
            INSTANCE_GROUP_MANAGER_TEMPLATE.format(
                id=1, name="igm-1", project="project1", template="it-1")),
        json.loads(
            KE_INSTANCE_GROUP_MANAGER_TEMPLATE.format(
                id=2, name="gke-cluster-1-default-pool-12345678-grp",
                project="project1",
                template="gke-cluster-1-default-pool-12345678",
                zone="us-central1-a")),
    ]
}

# Fields: id, name, project, network, num
INSTANCE_TEMPLATES_TEMPLATE = """
{{
 "kind": "compute#instanceTemplate",
 "id": "113{id}",
 "creationTimestamp": "2017-05-26T22:07:36.275-07:00",
 "name": "{name}",
 "description": "",
 "properties": {{
  "tags": {{
   "items": [
    "iap-tag"
   ]
  }},
  "machineType": "f1-micro",
  "canIpForward": false,
  "networkInterfaces": [
   {{
    "kind": "compute#networkInterface",
    "network": "https://www.googleapis.com/compute/v1/projects/{project}/global/networks/{network}",
    "accessConfigs": [
     {{
      "kind": "compute#accessConfig",
      "type": "ONE_TO_ONE_NAT",
      "name": "External NAT"
     }}
    ]
   }}
  ],
  "disks": [
   {{
    "kind": "compute#attachedDisk",
    "type": "PERSISTENT",
    "mode": "READ_WRITE",
    "deviceName": "{name}",
    "boot": true,
    "initializeParams": {{
     "sourceImage": "projects/debian-cloud/global/images/debian-8-jessie-v20170523",
     "diskSizeGb": "10",
     "diskType": "pd-standard"
    }},
    "autoDelete": true
   }}
  ],
  "metadata": {{
   "kind": "compute#metadata",
   "fingerprint": "Ab2_F_dLE3A="
  }},
  "serviceAccounts": [
   {{
    "email": "{num}-compute@developer.gserviceaccount.com",
    "scopes": [
     "https://www.googleapis.com/auth/devstorage.read_only",
     "https://www.googleapis.com/auth/logging.write",
     "https://www.googleapis.com/auth/monitoring.write",
     "https://www.googleapis.com/auth/servicecontrol",
     "https://www.googleapis.com/auth/service.management.readonly",
     "https://www.googleapis.com/auth/trace.append"
    ]
   }}
  ],
  "scheduling": {{
   "onHostMaintenance": "MIGRATE",
   "automaticRestart": true,
   "preemptible": false
  }}
 }},
 "selfLink": "https://www.googleapis.com/compute/v1/projects/{project}/global/instanceTemplates/{name}"
}}
"""

GCE_GET_INSTANCE_TEMPLATES = {
    PROJECT_ID_PREFIX + "1": [
        json.loads(
            INSTANCE_TEMPLATES_TEMPLATE.format(
                id=1,
                name="it-1",
                project="project1",
                network="default",
                num=PROJECT_ID_PREFIX + "1")),
        json.loads(
            INSTANCE_TEMPLATES_TEMPLATE.format(
                id=2,
                name="gke-cluster-1-default-pool-12345678",
                project="project1",
                network="default",
                num=PROJECT_ID_PREFIX + "1")),
    ]
}

# Fields: id, name, project
NETWORK_TEMPLATE = """
{{
 "kind": "compute#network",
 "id": "114{id}",
 "creationTimestamp": "2017-09-25T12:33:24.312-07:00",
 "name": "{name}",
 "description": "",
 "selfLink": "https://www.googleapis.com/compute/v1/projects/{project}/global/networks/{name}",
 "autoCreateSubnetworks": true,
 "subnetworks": [
  "https://www.googleapis.com/compute/v1/projects/{project}/regions/europe-west1/subnetworks/{name}",
  "https://www.googleapis.com/compute/v1/projects/{project}/regions/asia-east1/subnetworks/{name}",
  "https://www.googleapis.com/compute/v1/projects/{project}/regions/us-west1/subnetworks/{name}",
  "https://www.googleapis.com/compute/v1/projects/{project}/regions/asia-northeast1/subnetworks/{name}",
  "https://www.googleapis.com/compute/v1/projects/{project}/regions/us-central1/subnetworks/{name}",
  "https://www.googleapis.com/compute/v1/projects/{project}/regions/southamerica-east1/subnetworks/{name}",
  "https://www.googleapis.com/compute/v1/projects/{project}/regions/europe-west3/subnetworks/{name}",
  "https://www.googleapis.com/compute/v1/projects/{project}/regions/us-east1/subnetworks/{name}",
  "https://www.googleapis.com/compute/v1/projects/{project}/regions/us-east4/subnetworks/{name}",
  "https://www.googleapis.com/compute/v1/projects/{project}/regions/europe-west2/subnetworks/{name}",
  "https://www.googleapis.com/compute/v1/projects/{project}/regions/asia-southeast1/subnetworks/{name}",
  "https://www.googleapis.com/compute/v1/projects/{project}/regions/australia-southeast1/subnetworks/{name}"
 ]
}}
"""

GCE_GET_NETWORKS = {
    PROJECT_ID_PREFIX + "1": [
        json.loads(
            NETWORK_TEMPLATE.format(id=1, name="default", project="project1")),
    ],
    PROJECT_ID_PREFIX + "2": [
        json.loads(
            NETWORK_TEMPLATE.format(id=2, name="default", project="project2")),
    ]
}


# Fields: id, name, project, zone
SNAPSHOT_TEMPLATE = """
{{
 "kind": "compute#snapshot",
 "id": "119{id}",
 "creationTimestamp": "2018-07-12T13:32:03.912-07:00",
 "name": "{name}",
 "description": "",
 "status": "READY",
 "sourceDisk": "https://www.googleapis.com/compute/beta/projects/{project}/zones/{zone}/disks/{name}",
 "sourceDiskId": "7102445878994667099",
 "diskSizeGb": "10",
 "storageBytes": "536550912",
 "storageBytesStatus": "UP_TO_DATE",
 "licenses": [
  "https://www.googleapis.com/compute/beta/projects/debian-cloud/global/licenses/debian-9-stretch"
 ],
 "selfLink": "https://www.googleapis.com/compute/beta/projects/{project}/global/snapshots/{name}",
 "labelFingerprint": "foofoo456",
 "licenseCodes": [
  "1000205"
 ],
 "storageLocations": [
  "us"
 ]
}}
"""

GCE_GET_SNAPSHOTS = {
    PROJECT_ID_PREFIX + "1": [
        json.loads(SNAPSHOT_TEMPLATE.format(id=1, name='snap-1', project='project1', zone='us-east1-b')),
        json.loads(SNAPSHOT_TEMPLATE.format(id=2, name='snap-2', project='project1', zone='europe-west4-a'))
    ],
    PROJECT_ID_PREFIX + "2": [
        json.loads(SNAPSHOT_TEMPLATE.format(id=3, name='snap-1', project='project2', zone='asia-south1-c')),
    ]
}

# Fields: id, name, project, ippart, region
SUBNETWORK_TEMPLATE = """
{{
 "kind": "compute#subnetwork",
 "id": "115{id}",
 "creationTimestamp": "2017-03-27T15:45:47.874-07:00",
 "name": "{name}",
 "network": "https://www.googleapis.com/compute/v1/projects/{project}/global/networks/{name}",
 "ipCidrRange": "10.{ippart}.0.0/20",
 "gatewayAddress": "10.{ippart}.0.1",
 "region": "https://www.googleapis.com/compute/v1/projects/{project}/regions/{region}",
 "selfLink": "https://www.googleapis.com/compute/v1/projects/{project}/regions/{region}/subnetworks/{name}",
 "privateIpGoogleAccess": false
}}
"""


def _generate_subnetworks(project, startid):
    """Generate one subnetwork resource per region."""
    subnetworks = []
    ippart = 128
    id = startid
    for region in ["asia-east1", "asia-northeast1", "asia-southeast1",
                   "australia-southeast1", "europe-west1", "europe-west2",
                   "europe-west3", "southamerica-east1", "us-central1",
                   "us-east1", "us-east4", "us-west1"]:
        subnetworks.append(
            json.loads(
                SUBNETWORK_TEMPLATE.format(
                    id=id, name="default", project=project, ippart=ippart,
                    region=region)))
        ippart += 4
        id += 1
    return subnetworks


GCE_GET_SUBNETWORKS = {
    PROJECT_ID_PREFIX + "1": _generate_subnetworks("project1", 10),
    PROJECT_ID_PREFIX + "2": _generate_subnetworks("project2", 30),
}

# Fields: name, num
GCS_BUCKET_TEMPLATE = """
{{
 "kind": "storage#bucket",
 "id": "{name}",
 "selfLink": "https://www.googleapis.com/storage/v1/b/{name}",
 "projectNumber": "{num}",
 "name": "{name}",
 "timeCreated": "2017-01-18T18:57:23.536Z",
 "updated": "2017-01-18T18:57:23.536Z",
 "metageneration": "1",
 "acl": [
  {{
   "kind": "storage#bucketAccessControl",
   "id": "{name}/project-owners-{num}",
   "selfLink": "https://www.googleapis.com/storage/v1/b/{name}/acl/project-owners-{num}",
   "bucket": "{name}",
   "entity": "project-owners-{num}",
   "role": "OWNER",
   "projectTeam": {{
    "projectNumber": "{num}",
    "team": "owners"
   }},
   "etag": "CAE="
  }},
  {{
   "kind": "storage#bucketAccessControl",
   "id": "{name}/project-editors-{num}",
   "selfLink": "https://www.googleapis.com/storage/v1/b/{name}/acl/project-editors-{num}",
   "bucket": "{name}",
   "entity": "project-editors-{num}",
   "role": "OWNER",
   "projectTeam": {{
    "projectNumber": "{num}",
    "team": "editors"
   }},
   "etag": "CAE="
  }},
  {{
   "kind": "storage#bucketAccessControl",
   "id": "{name}/project-viewers-{num}",
   "selfLink": "https://www.googleapis.com/storage/v1/b/{name}/acl/project-viewers-{num}",
   "bucket": "{name}",
   "entity": "project-viewers-{num}",
   "role": "READER",
   "projectTeam": {{
    "projectNumber": "{num}",
    "team": "viewers"
   }},
   "etag": "CAE="
  }}
 ],
 "defaultObjectAcl": [
  {{
   "kind": "storage#objectAccessControl",
   "entity": "project-owners-{num}",
   "role": "OWNER",
   "projectTeam": {{
    "projectNumber": "{num}",
    "team": "owners"
   }},
   "etag": "CAE="
  }},
  {{
   "kind": "storage#objectAccessControl",
   "entity": "project-editors-{num}",
   "role": "OWNER",
   "projectTeam": {{
    "projectNumber": "{num}",
    "team": "editors"
   }},
   "etag": "CAE="
  }},
  {{
   "kind": "storage#objectAccessControl",
   "entity": "project-viewers-{num}",
   "role": "READER",
   "projectTeam": {{
    "projectNumber": "{num}",
    "team": "viewers"
   }},
   "etag": "CAE="
  }}
 ],
 "owner": {{
  "entity": "project-owners-{num}"
 }},
 "location": "US",
 "storageClass": "STANDARD",
 "etag": "CAE="
}}
"""

GCS_GET_BUCKETS = {
    PROJECT_ID_PREFIX + "3": [
        json.loads(
            GCS_BUCKET_TEMPLATE.format(
                name="bucket1", num=PROJECT_ID_PREFIX + "3")),
    ],
    PROJECT_ID_PREFIX + "4": [
        json.loads(
            GCS_BUCKET_TEMPLATE.format(
                name="bucket2", num=PROJECT_ID_PREFIX + "4")),
    ]
}

GCS_GET_OBJECTS = {}

BUCKET_IAM_TEMPLATE = """
{{
 "bindings": [
  {{
   "role": "roles/storage.legacyBucketOwner",
   "members": [
    "projectEditor:{project}",
    "projectOwner:{project}"
   ]
  }},
  {{
   "role": "roles/storage.legacyBucketReader",
   "members": [
    "projectViewer:{project}"
   ]
  }}
 ],
 "etag": "CAE="
}}
"""

GCS_GET_BUCKET_IAM = {
    "bucket1":
        json.loads(
            BUCKET_IAM_TEMPLATE.format(name="bucket1", project="project3")),
    "bucket2":
        json.loads(
            BUCKET_IAM_TEMPLATE.format(name="bucket2", project="project4"))
}

GCS_GET_OBJECT_IAM = {}

# Fields: project, num, id
SERVICEACCOUNT_TEMPLATE = """
{{
 "name": "projects/{project}/serviceAccounts/{num}-compute@developer.gserviceaccount.com",
 "projectId": "{project}",
 "uniqueId": "110{id}",
 "email": "{num}-compute@developer.gserviceaccount.com",
 "displayName": "Compute Engine default service account",
 "etag": "etag",
 "oauth2ClientId": "110{id}"
}}
"""

IAM_GET_SERVICEACCOUNTS = {
    "project1": [
        json.loads(
            SERVICEACCOUNT_TEMPLATE.format(
                project="project1", num=PROJECT_ID_PREFIX + "1", id=1)),
    ],
    "project2": [
        json.loads(
            SERVICEACCOUNT_TEMPLATE.format(
                project="project2", num=PROJECT_ID_PREFIX + "2", id=2)),
    ],
}

SERVICEACCOUNT_IAM_POLICY = """
{
 "bindings": [
  {
   "role": "roles/iam.serviceAccountKeyAdmin",
   "members": [
    "user:c_user@forseti.test"
   ]
  }
 ]
}
"""

SERVICEACCOUNT_EMPTY_IAM_POLICY = """
{
 "etag": "ACAB"
}
"""

SERVICEACCOUNT1 = IAM_GET_SERVICEACCOUNTS["project1"][0]["name"]
SERVICEACCOUNT2 = IAM_GET_SERVICEACCOUNTS["project2"][0]["name"]

IAM_GET_SERVICEACCOUNT_IAM_POLICY = {
    SERVICEACCOUNT1: json.loads(SERVICEACCOUNT_IAM_POLICY),
    SERVICEACCOUNT2: json.loads(SERVICEACCOUNT_EMPTY_IAM_POLICY),
}

# Fields: sa_name, id
SERVICEACCOUNT_EXPORT_KEY_TEMPLATE = """
{{
 "name": "{sa_name}/keys/116{id}",
 "validAfterTime": "2017-11-22T17:49:56Z",
 "validBeforeTime": "2027-11-20T17:49:56Z",
 "keyAlgorithm": "KEY_ALG_RSA_2048"
}}
"""

IAM_GET_SERVICEACCOUNT_KEYS = {
    SERVICEACCOUNT1: [
        json.loads(
            SERVICEACCOUNT_EXPORT_KEY_TEMPLATE.format(
                sa_name=SERVICEACCOUNT1, id=1)),
    ],
}

CONTAINER_SERVERCONFIG = """
{
  "defaultClusterVersion": "1.7.11-gke.1",
  "validNodeVersions": [
    "1.8.6-gke.0",
    "1.8.5-gke.0",
    "1.8.4-gke.1",
    "1.8.3-gke.0",
    "1.8.2-gke.0",
    "1.8.1-gke.1",
    "1.7.12-gke.0",
    "1.7.11-gke.1",
    "1.7.11",
    "1.7.10-gke.0",
    "1.7.8-gke.0",
    "1.6.13-gke.1",
    "1.6.11-gke.0",
    "1.5.7"
  ],
  "defaultImageType": "COS",
  "validImageTypes": [
    "UBUNTU",
    "COS"
  ],
  "validMasterVersions": [
    "1.8.6-gke.0",
    "1.8.5-gke.0",
    "1.7.12-gke.0",
    "1.7.11-gke.1"
  ]
}
"""

# Fields: project, cl_name, np_name, zone
CONTAINER_CLUSTERS_TEMPLATE = """
{{
  "name": "{cl_name}",
  "nodeConfig": {{
    "machineType": "n1-standard-1",
    "diskSizeGb": 100,
    "oauthScopes": [
      "https://www.googleapis.com/auth/compute",
      "https://www.googleapis.com/auth/devstorage.read_only",
      "https://www.googleapis.com/auth/logging.write",
      "https://www.googleapis.com/auth/monitoring",
      "https://www.googleapis.com/auth/servicecontrol",
      "https://www.googleapis.com/auth/service.management.readonly",
      "https://www.googleapis.com/auth/trace.append"
    ],
    "imageType": "COS",
    "serviceAccount": "default"
  }},
  "masterAuth": {{
    "username": "user",
    "password": "pass",
    "clusterCaCertificate": "AB",
    "clientCertificate": "AB",
    "clientKey": "AB"
  }},
  "loggingService": "logging.googleapis.com",
  "monitoringService": "none",
  "network": "default",
  "clusterIpv4Cidr": "10.8.0.0/14",
  "addonsConfig": {{
    "httpLoadBalancing": {{}},
    "kubernetesDashboard": {{}},
    "networkPolicyConfig": {{
      "disabled": true
    }}
  }},
  "subnetwork": "default",
  "nodePools": [
    {{
      "name": "{np_name}",
      "config": {{
        "machineType": "n1-standard-1",
        "diskSizeGb": 100,
        "oauthScopes": [
          "https://www.googleapis.com/auth/compute",
          "https://www.googleapis.com/auth/devstorage.read_only",
          "https://www.googleapis.com/auth/logging.write",
          "https://www.googleapis.com/auth/monitoring",
          "https://www.googleapis.com/auth/servicecontrol",
          "https://www.googleapis.com/auth/service.management.readonly",
          "https://www.googleapis.com/auth/trace.append"
        ],
        "imageType": "COS",
        "serviceAccount": "default"
      }},
      "initialNodeCount": 3,
      "autoscaling": {{}},
      "management": {{
        "autoUpgrade": true
      }},
      "selfLink": "https://container.googleapis.com/v1/projects/{project}/zones/{zone}/clusters/{cl_name}/nodePools/{np_name}",
      "version": "1.7.11-gke.1",
      "instanceGroupUrls": [
        "https://www.googleapis.com/compute/v1/projects/{project}/zones/{zone}/instanceGroupManagers/gke-{cl_name}-{np_name}-12345678-grp"
      ],
      "status": "RUNNING"
    }}
  ],
  "locations": [
    "us-central1-a"
  ],
  "labelFingerprint": "abcdef12",
  "legacyAbac": {{}},
  "networkPolicy": {{
    "provider": "CALICO"
  }},
  "ipAllocationPolicy": {{}},
  "masterAuthorizedNetworksConfig": {{}},
  "selfLink": "https://container.googleapis.com/v1/projects/{project}/zones/{zone}/clusters/{cl_name}",
  "zone": "{zone}",
  "endpoint": "10.0.0.1",
  "initialClusterVersion": "1.7.6-gke.1",
  "currentMasterVersion": "1.7.11-gke.1",
  "currentNodeVersion": "1.7.11-gke.1",
  "createTime": "2017-10-24T19:36:21+00:00",
  "status": "RUNNING",
  "nodeIpv4CidrSize": 24,
  "servicesIpv4Cidr": "10.11.240.0/20",
  "instanceGroupUrls": [
    "https://www.googleapis.com/compute/v1/projects/{project}/zones/{zone}/instanceGroupManagers/gke-{cl_name}-{np_name}-12345678-grp"
  ],
  "currentNodeCount": 3
}}
"""

KE_GET_CLUSTERS = {
    PROJECT_ID_PREFIX + "1": [
        json.loads(
            CONTAINER_CLUSTERS_TEMPLATE.format(
                project="project1", cl_name="cluster-1", np_name="default-pool",
                zone="us-central1-a")),
    ],
}

KE_GET_SERVICECONFIG = {
    "us-central1-a": json.loads(CONTAINER_SERVERCONFIG),
}

# Fields: project, role
PROJECT_ROLES_TEMPLATE = """
{{
 "name": "projects/{project}/roles/{role}",
 "title": "{role}",
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
}}
"""

IAM_GET_PROJECT_ROLES = {
    "project4": [
        json.loads(
            PROJECT_ROLES_TEMPLATE.format(project="project4", role="role1")),
    ]
}

# Fields: orgid, role
ORG_ROLES_TEMPLATE = """
{{
 "name": "{orgid}/roles/{role}",
 "title": "{role}",
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
}}
"""

IAM_GET_ORG_ROLES = {
    ORGANIZATION_ID: [
        json.loads(
            ORG_ROLES_TEMPLATE.format(orgid=ORGANIZATION_ID, role="role2")),
    ]
}

IAM_GET_CURATED_ROLES = [{
    "name":
        "roles/appengine.appAdmin",
    "title":
        "App Engine Admin",
    "description":
        "Full management of App Engine apps (but not storage).",
    "includedPermissions": [
        "appengine.applications.disable", "appengine.applications.get",
        "appengine.applications.update", "appengine.instances.delete",
        "appengine.instances.get", "appengine.instances.list",
        "appengine.instances.update", "appengine.operations.cancel",
        "appengine.operations.delete", "appengine.operations.get",
        "appengine.operations.list", "appengine.runtimes.actAsAdmin",
        "appengine.services.delete", "appengine.services.get",
        "appengine.services.list", "appengine.services.update",
        "appengine.versions.create", "appengine.versions.delete",
        "appengine.versions.get", "appengine.versions.list",
        "appengine.versions.update", "resourcemanager.projects.get",
        "resourcemanager.projects.list"
    ],
    "stage":
        "GA",
    "etag":
        "AA=="
}, {
    "name":
        "roles/appengine.appViewer",
    "title":
        "App Engine Viewer",
    "description":
        "Ability to view App Engine app status.",
    "includedPermissions": [
        "appengine.applications.get", "appengine.instances.get",
        "appengine.instances.list", "appengine.operations.get",
        "appengine.operations.list", "appengine.services.get",
        "appengine.services.list", "appengine.versions.get",
        "appengine.versions.list", "resourcemanager.projects.get",
        "resourcemanager.projects.list"
    ],
    "stage":
        "GA",
    "etag":
        "AA=="
}, {
    "name":
        "roles/appengine.codeViewer",
    "title":
        "App Engine Code Viewer",
    "description":
        "Ability to view App Engine app status and deployed source code.",
    "includedPermissions": [
        "appengine.applications.get", "appengine.instances.get",
        "appengine.instances.list", "appengine.operations.get",
        "appengine.operations.list", "appengine.services.get",
        "appengine.services.list", "appengine.versions.get",
        "appengine.versions.getFileContents", "appengine.versions.list",
        "resourcemanager.projects.get", "resourcemanager.projects.list"
    ],
    "stage":
        "GA",
    "etag":
        "AA=="
}]

# Fields: project
BILLING_ENABLED_TEMPLATE = """
{{
 "name": "projects/{project}/billingInfo",
 "projectId": "{project}",
 "billingAccountName": "billingAccounts/000000-111111-222222",
 "billingEnabled": true
}}
"""

# Fields: project
BILLING_DISABLED_TEMPLATE = """
{{
 "name": "projects/{project}/billingInfo",
 "projectId": "{project}"
}}
"""

BILLING_GET_INFO = {
    PROJECT_ID_PREFIX + "1":
        json.loads(
            BILLING_ENABLED_TEMPLATE.format(project="project1")),
    PROJECT_ID_PREFIX + "2":
        json.loads(
            BILLING_ENABLED_TEMPLATE.format(project="project2")),
    PROJECT_ID_PREFIX + "3":
        json.loads(
            BILLING_ENABLED_TEMPLATE.format(project="project3")),
    PROJECT_ID_PREFIX + "4":
        json.loads(
            BILLING_DISABLED_TEMPLATE.format(project="project4")),
}

BILLING_MASTER_ACCOUNT = "001122-AABBCC-DDEEFF"
BILLING_TEAM_ACCOUNT = "000000-111111-222222"

BILLING_GET_ACCOUNTS = [{
    "name": "billingAccounts/" + BILLING_MASTER_ACCOUNT,
    "open": True,
    "displayName": "Master Billing Account",
}, {
    "name": "billingAccounts/" + BILLING_TEAM_ACCOUNT,
    "open": True,
    "displayName": "Team Billing Account",
    "masterBillingAccount": "billingAccounts/" + BILLING_MASTER_ACCOUNT,
}]

# Fields: admin
BILLING_IAM_POLICY_TEMPLATE = """
{{
 "etag": "BcDe123456z=",
 "bindings": [
  {{
   "role": "roles/billing.admin",
   "members": [
    "user:{admin}"
   ]
  }},
  {{
   "role": "roles/logging.viewer",
   "members": [
    "group:auditors@forseti.test"
   ]
  }}
 ]
}}
"""

BILLING_IAM_POLICIES = {
   "billingAccounts/" + BILLING_MASTER_ACCOUNT: json.loads(
       BILLING_IAM_POLICY_TEMPLATE.format(admin="org-admin@forseti.test")),
   "billingAccounts/" + BILLING_TEAM_ACCOUNT: json.loads(
       BILLING_IAM_POLICY_TEMPLATE.format(admin="team-admin@forseti.test")),
}

APPENGINE_API_ENABLED = """
{
 "serviceName": "appengine.googleapis.com",
 "producerProjectId": "google.com:elegant-theorem-93918"
}
"""

BIGQUERY_API_ENABLED = """
{
 "serviceName": "bigquery-json.googleapis.com",
 "producerProjectId": "google.com:ultra-current-88221"
}
"""

CLOUDSQL_API_ENABLED = """
{
 "serviceName": "sql-component.googleapis.com",
 "producerProjectId": "google.com:prod-default-producer-project"
}
"""

COMPUTE_API_ENABLED = """
{
 "serviceName": "compute.googleapis.com",
 "producerProjectId": "google.com:api-project-539346026206"
}
"""

CONTAINER_API_ENABLED = """
{
 "serviceName": "container.googleapis.com",
 "producerProjectId": "google.com:cloud-kubernetes-devrel"
}
"""

STORAGE_API_ENABLED = """
{
 "serviceName": "storage-component.googleapis.com",
 "producerProjectId": "google.com:prod-default-producer-project"
}
"""

SERVICEMANAGEMENT_ENABLED_APIS = {
    PROJECT_ID_PREFIX + "1": [
        json.loads(STORAGE_API_ENABLED),
        json.loads(COMPUTE_API_ENABLED),
        json.loads(CONTAINER_API_ENABLED),
    ],
    PROJECT_ID_PREFIX + "2": [
        json.loads(STORAGE_API_ENABLED),
        json.loads(COMPUTE_API_ENABLED),
        json.loads(CLOUDSQL_API_ENABLED),
    ],
    PROJECT_ID_PREFIX + "3": [
        json.loads(STORAGE_API_ENABLED),
        json.loads(BIGQUERY_API_ENABLED),
    ],
    PROJECT_ID_PREFIX + "4": [
        json.loads(STORAGE_API_ENABLED),
        json.loads(APPENGINE_API_ENABLED),
    ],
}

# Fields: name, destination
LOG_SINK_TEMPLATE = """
{{
 "name": "{name}",
 "destination": "{destination}",
 "filter": "logName:\\\"logs/cloudaudit.googleapis.com\\\"",
 "outputVersionFormat": "V2",
 "writerIdentity": "serviceAccount:{name}@logging-1234.iam.gserviceaccount.com"
}}
"""

# Fields: name, destination
LOG_SINK_TEMPLATE_NO_FILTER = """
{{
 "name": "{name}",
 "destination": "{destination}",
 "outputVersionFormat": "V2",
 "writerIdentity": "serviceAccount:{name}@logging-1234.iam.gserviceaccount.com"
}}
"""

# Fields: name, destination
LOG_SINK_TEMPLATE_INCL_CHILDREN = """
{{
 "name": "{name}",
 "destination": "{destination}",
 "outputVersionFormat": "V2",
 "filter": "logName:\\\"logs/cloudaudit.googleapis.com\\\"",
 "includeChildren": true,
 "writerIdentity": "serviceAccount:cloud-logs@system.gserviceaccount.com"
}}
"""

LOGGING_GET_ORG_SINKS = {
    ORGANIZATION_ID: [
        json.loads(
            LOG_SINK_TEMPLATE.format(
                name="org-audit-logs",
                destination="storage.googleapis.com/my_org_logs")),
    ]
}

LOGGING_GET_FOLDER_SINKS = {
    "folders/" + FOLDER_ID_PREFIX + "1": [
        json.loads(
            LOG_SINK_TEMPLATE.format(
                name="folder-logs", destination=(
                    "pubsub.googleapis.com/projects/project1/topics/f1-logs"))),
    ],
    "folders/" + FOLDER_ID_PREFIX + "2": [
        json.loads(
            LOG_SINK_TEMPLATE_INCL_CHILDREN.format(
                name="folder-logs",
                destination="storage.googleapis.com/my_folder_logs")),
    ]
}
LOGGING_GET_BILLING_ACCOUNT_SINKS = {
    "billingAccounts/" + BILLING_TEAM_ACCOUNT: [
        json.loads(
            LOG_SINK_TEMPLATE.format(
                name="billing-audit-logs",
                destination="storage.googleapis.com/b001122_logs")),
    ]
}

LOGGING_GET_PROJECT_SINKS = {
    PROJECT_ID_PREFIX + "1": [
        json.loads(
            LOG_SINK_TEMPLATE.format(
                name="logs-to-bigquery", destination=(
                    "bigquery.googleapis.com/projects/project1/"
                    "datasets/audit_logs"))),
        json.loads(
            LOG_SINK_TEMPLATE_NO_FILTER.format(
                name="logs-to-gcs",
                destination="storage.googleapis.com/project1_logs")),
    ],
    PROJECT_ID_PREFIX + "2": [
        json.loads(
            LOG_SINK_TEMPLATE.format(
                name="logs-to-gcs",
                destination="storage.googleapis.com/project2_logs")),
    ]
}
