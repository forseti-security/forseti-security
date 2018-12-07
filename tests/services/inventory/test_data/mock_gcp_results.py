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
},
{
 "name": "roles/bigquery.dataEditor",
 "title": "BigQuery Data Editor",
 "description": "Access to edit all the tables in datasets",
 "includedPermissions": [
  "bigquery.datasets.create",
  "bigquery.datasets.get",
  "bigquery.datasets.getIamPolicy",
  "bigquery.tables.create",
  "bigquery.tables.delete",
  "bigquery.tables.export",
  "bigquery.tables.get",
  "bigquery.tables.getData",
  "bigquery.tables.list",
  "bigquery.tables.update",
  "bigquery.tables.updateData",
  "resourcemanager.projects.get",
  "resourcemanager.projects.list"
 ],
 "stage": "GA",
 "etag": "AA=="
},
{
 "name": "roles/bigquery.dataOwner",
 "title": "BigQuery Data Owner",
 "description": "Full access to datasets and all its tables",
 "includedPermissions": [
  "bigquery.datasets.create",
  "bigquery.datasets.delete",
  "bigquery.datasets.get",
  "bigquery.datasets.getIamPolicy",
  "bigquery.datasets.setIamPolicy",
  "bigquery.datasets.update",
  "bigquery.tables.create",
  "bigquery.tables.delete",
  "bigquery.tables.export",
  "bigquery.tables.get",
  "bigquery.tables.getData",
  "bigquery.tables.list",
  "bigquery.tables.update",
  "bigquery.tables.updateData",
  "resourcemanager.projects.get",
  "resourcemanager.projects.list"
 ],
 "stage": "GA",
 "etag": "AA=="
},
{
 "name": "roles/bigquery.dataViewer",
 "title": "BigQuery Data Viewer",
 "description": "Access to view datasets and all its tables",
 "includedPermissions": [
  "bigquery.datasets.get",
  "bigquery.datasets.getIamPolicy",
  "bigquery.tables.export",
  "bigquery.tables.get",
  "bigquery.tables.getData",
  "bigquery.tables.list",
  "resourcemanager.projects.get",
  "resourcemanager.projects.list"
 ],
 "stage": "GA",
 "etag": "AA=="
},
{
 "name": "roles/billing.admin",
 "title": "Billing Account Administrator",
 "description": "Authorized to see and manage all aspects of billing accounts.",
 "includedPermissions": [
  "billing.accounts.close",
  "billing.accounts.get",
  "billing.accounts.getIamPolicy",
  "billing.accounts.getPaymentInfo",
  "billing.accounts.getSpendingInformation",
  "billing.accounts.getUsageExportSpec",
  "billing.accounts.list",
  "billing.accounts.move",
  "billing.accounts.redeemPromotion",
  "billing.accounts.removeFromOrganization",
  "billing.accounts.reopen",
  "billing.accounts.setIamPolicy",
  "billing.accounts.update",
  "billing.accounts.updatePaymentInfo",
  "billing.accounts.updateUsageExportSpec",
  "billing.budgets.create",
  "billing.budgets.delete",
  "billing.budgets.get",
  "billing.budgets.list",
  "billing.budgets.update",
  "billing.credits.list",
  "billing.resourceAssociations.create",
  "billing.resourceAssociations.delete",
  "billing.resourceAssociations.list",
  "billing.subscriptions.create",
  "billing.subscriptions.get",
  "billing.subscriptions.list",
  "billing.subscriptions.update",
  "cloudnotifications.activities.list",
  "logging.logEntries.list",
  "logging.logServiceIndexes.list",
  "logging.logServices.list",
  "logging.logs.list",
  "logging.privateLogEntries.list",
  "resourcemanager.projects.createBillingAssignment",
  "resourcemanager.projects.deleteBillingAssignment"
 ],
 "stage": "GA",
 "etag": "AA=="
},
{
 "name": "roles/cloudkms.admin",
 "title": "Cloud KMS Admin",
 "description": "Enables management of crypto resources.",
 "includedPermissions": [
  "cloudkms.cryptoKeyVersions.create",
  "cloudkms.cryptoKeyVersions.destroy",
  "cloudkms.cryptoKeyVersions.get",
  "cloudkms.cryptoKeyVersions.list",
  "cloudkms.cryptoKeyVersions.restore",
  "cloudkms.cryptoKeyVersions.update",
  "cloudkms.cryptoKeys.create",
  "cloudkms.cryptoKeys.get",
  "cloudkms.cryptoKeys.getIamPolicy",
  "cloudkms.cryptoKeys.list",
  "cloudkms.cryptoKeys.setIamPolicy",
  "cloudkms.cryptoKeys.update",
  "cloudkms.keyRings.create",
  "cloudkms.keyRings.get",
  "cloudkms.keyRings.getIamPolicy",
  "cloudkms.keyRings.list",
  "cloudkms.keyRings.setIamPolicy",
  "resourcemanager.projects.get"
 ],
 "stage": "GA",
 "etag": "AA=="
},
{
 "name": "roles/cloudkms.cryptoKeyEncrypterDecrypter",
 "title": "Cloud KMS CryptoKey Encrypter/Decrypter",
 "description": "Enables Encrypt and Decrypt operations",
 "includedPermissions": [
  "cloudkms.cryptoKeyVersions.useToDecrypt",
  "cloudkms.cryptoKeyVersions.useToEncrypt",
  "resourcemanager.projects.get"
 ],
 "stage": "GA",
 "etag": "AA=="
},
{
 "name": "roles/editor",
 "title": "Editor",
 "description": "Edit access to all resources.",
 "includedPermissions": [
  "accesscontextmanager.accessLevels.create",
  "accesscontextmanager.accessLevels.delete",
  "accesscontextmanager.accessLevels.get",
  "accesscontextmanager.accessLevels.list",
  "accesscontextmanager.accessLevels.update",
  "accesscontextmanager.accessPolicies.create",
  "accesscontextmanager.accessPolicies.delete",
  "accesscontextmanager.accessPolicies.get",
  "accesscontextmanager.accessPolicies.getIamPolicy",
  "accesscontextmanager.accessPolicies.list",
  "accesscontextmanager.accessPolicies.update",
  "accesscontextmanager.accessZones.create",
  "accesscontextmanager.accessZones.delete",
  "accesscontextmanager.accessZones.get",
  "accesscontextmanager.accessZones.list",
  "accesscontextmanager.accessZones.update",
  "accesscontextmanager.policies.create",
  "accesscontextmanager.policies.delete",
  "accesscontextmanager.policies.get",
  "accesscontextmanager.policies.getIamPolicy",
  "accesscontextmanager.policies.list",
  "accesscontextmanager.policies.update",
  "accesscontextmanager.servicePerimeters.create",
  "accesscontextmanager.servicePerimeters.delete",
  "accesscontextmanager.servicePerimeters.get",
  "accesscontextmanager.servicePerimeters.list",
  "accesscontextmanager.servicePerimeters.update",
  "androidmanagement.enterprises.manage",
  "appengine.applications.get",
  "appengine.applications.update",
  "appengine.instances.delete",
  "appengine.instances.get",
  "appengine.instances.list",
  "appengine.memcache.addKey",
  "appengine.memcache.flush",
  "appengine.memcache.get",
  "appengine.memcache.getKey",
  "appengine.memcache.list",
  "appengine.memcache.update",
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
  "automl.annotationSpecs.create",
  "automl.annotationSpecs.delete",
  "automl.annotationSpecs.get",
  "automl.annotationSpecs.list",
  "automl.annotationSpecs.update",
  "automl.annotations.approve",
  "automl.annotations.create",
  "automl.annotations.list",
  "automl.annotations.manipulate",
  "automl.annotations.reject",
  "automl.datasets.create",
  "automl.datasets.delete",
  "automl.datasets.export",
  "automl.datasets.get",
  "automl.datasets.getIamPolicy",
  "automl.datasets.import",
  "automl.datasets.list",
  "automl.examples.delete",
  "automl.examples.get",
  "automl.examples.list",
  "automl.humanAnnotationTasks.create",
  "automl.humanAnnotationTasks.delete",
  "automl.humanAnnotationTasks.get",
  "automl.humanAnnotationTasks.list",
  "automl.locations.get",
  "automl.locations.getIamPolicy",
  "automl.locations.list",
  "automl.modelEvaluations.create",
  "automl.modelEvaluations.get",
  "automl.modelEvaluations.list",
  "automl.models.create",
  "automl.models.delete",
  "automl.models.deploy",
  "automl.models.get",
  "automl.models.getIamPolicy",
  "automl.models.list",
  "automl.models.predict",
  "automl.models.undeploy",
  "automl.operations.cancel",
  "automl.operations.delete",
  "automl.operations.get",
  "automl.operations.list",
  "bigquery.config.get",
  "bigquery.datasets.create",
  "bigquery.datasets.get",
  "bigquery.datasets.getIamPolicy",
  "bigquery.jobs.create",
  "bigquery.jobs.get",
  "bigquery.jobs.list",
  "bigquery.readsessions.create",
  "bigquery.savedqueries.create",
  "bigquery.savedqueries.delete",
  "bigquery.savedqueries.get",
  "bigquery.savedqueries.list",
  "bigquery.savedqueries.update",
  "bigquery.transfers.get",
  "bigquery.transfers.update",
  "bigtable.appProfiles.create",
  "bigtable.appProfiles.delete",
  "bigtable.appProfiles.get",
  "bigtable.appProfiles.list",
  "bigtable.appProfiles.update",
  "bigtable.clusters.create",
  "bigtable.clusters.delete",
  "bigtable.clusters.get",
  "bigtable.clusters.list",
  "bigtable.clusters.update",
  "bigtable.instances.create",
  "bigtable.instances.delete",
  "bigtable.instances.get",
  "bigtable.instances.getIamPolicy",
  "bigtable.instances.list",
  "bigtable.instances.update",
  "bigtable.tables.checkConsistency",
  "bigtable.tables.create",
  "bigtable.tables.delete",
  "bigtable.tables.generateConsistencyToken",
  "bigtable.tables.get",
  "bigtable.tables.list",
  "bigtable.tables.mutateRows",
  "bigtable.tables.readRows",
  "bigtable.tables.sampleRowKeys",
  "bigtable.tables.update",
  "billing.resourceCosts.get",
  "binaryauthorization.attestors.create",
  "binaryauthorization.attestors.delete",
  "binaryauthorization.attestors.get",
  "binaryauthorization.attestors.getIamPolicy",
  "binaryauthorization.attestors.list",
  "binaryauthorization.attestors.update",
  "binaryauthorization.attestors.verifyImageAttested",
  "binaryauthorization.policy.get",
  "binaryauthorization.policy.getIamPolicy",
  "binaryauthorization.policy.update",
  "clientauthconfig.brands.create",
  "clientauthconfig.brands.delete",
  "clientauthconfig.brands.get",
  "clientauthconfig.brands.list",
  "clientauthconfig.brands.update",
  "clientauthconfig.clients.create",
  "clientauthconfig.clients.createSecret",
  "clientauthconfig.clients.delete",
  "clientauthconfig.clients.get",
  "clientauthconfig.clients.getWithSecret",
  "clientauthconfig.clients.list",
  "clientauthconfig.clients.listWithSecrets",
  "clientauthconfig.clients.undelete",
  "clientauthconfig.clients.update",
  "cloudasset.assets.exportAll",
  "cloudbuild.builds.create",
  "cloudbuild.builds.get",
  "cloudbuild.builds.list",
  "cloudbuild.builds.update",
  "cloudconfig.configs.get",
  "cloudconfig.configs.update",
  "clouddebugger.breakpoints.create",
  "clouddebugger.breakpoints.delete",
  "clouddebugger.breakpoints.get",
  "clouddebugger.breakpoints.list",
  "clouddebugger.breakpoints.listActive",
  "clouddebugger.breakpoints.update",
  "clouddebugger.debuggees.create",
  "clouddebugger.debuggees.list",
  "cloudfunctions.functions.call",
  "cloudfunctions.functions.create",
  "cloudfunctions.functions.delete",
  "cloudfunctions.functions.get",
  "cloudfunctions.functions.list",
  "cloudfunctions.functions.sourceCodeGet",
  "cloudfunctions.functions.sourceCodeSet",
  "cloudfunctions.functions.update",
  "cloudfunctions.locations.list",
  "cloudfunctions.operations.get",
  "cloudfunctions.operations.list",
  "cloudiot.devices.create",
  "cloudiot.devices.delete",
  "cloudiot.devices.get",
  "cloudiot.devices.list",
  "cloudiot.devices.update",
  "cloudiot.devices.updateConfig",
  "cloudiot.registries.create",
  "cloudiot.registries.delete",
  "cloudiot.registries.get",
  "cloudiot.registries.getIamPolicy",
  "cloudiot.registries.list",
  "cloudiot.registries.update",
  "cloudjobdiscovery.companies.create",
  "cloudjobdiscovery.companies.delete",
  "cloudjobdiscovery.companies.get",
  "cloudjobdiscovery.companies.list",
  "cloudjobdiscovery.companies.update",
  "cloudjobdiscovery.events.create",
  "cloudjobdiscovery.events.delete",
  "cloudjobdiscovery.events.get",
  "cloudjobdiscovery.events.list",
  "cloudjobdiscovery.events.update",
  "cloudjobdiscovery.jobs.create",
  "cloudjobdiscovery.jobs.delete",
  "cloudjobdiscovery.jobs.deleteByFilter",
  "cloudjobdiscovery.jobs.get",
  "cloudjobdiscovery.jobs.search",
  "cloudjobdiscovery.jobs.update",
  "cloudjobdiscovery.tools.access",
  "cloudkms.cryptoKeyVersions.create",
  "cloudkms.cryptoKeyVersions.get",
  "cloudkms.cryptoKeyVersions.list",
  "cloudkms.cryptoKeyVersions.update",
  "cloudkms.cryptoKeys.create",
  "cloudkms.cryptoKeys.get",
  "cloudkms.cryptoKeys.getIamPolicy",
  "cloudkms.cryptoKeys.list",
  "cloudkms.cryptoKeys.update",
  "cloudkms.keyRings.create",
  "cloudkms.keyRings.get",
  "cloudkms.keyRings.getIamPolicy",
  "cloudkms.keyRings.list",
  "cloudnotifications.activities.list",
  "cloudprivatecatalog.targets.get",
  "cloudprivatecatalogproducer.associations.create",
  "cloudprivatecatalogproducer.associations.delete",
  "cloudprivatecatalogproducer.associations.get",
  "cloudprivatecatalogproducer.associations.list",
  "cloudprivatecatalogproducer.catalogs.create",
  "cloudprivatecatalogproducer.catalogs.delete",
  "cloudprivatecatalogproducer.catalogs.get",
  "cloudprivatecatalogproducer.catalogs.getIamPolicy",
  "cloudprivatecatalogproducer.catalogs.list",
  "cloudprivatecatalogproducer.catalogs.undelete",
  "cloudprivatecatalogproducer.catalogs.update",
  "cloudprivatecatalogproducer.targets.associate",
  "cloudprivatecatalogproducer.targets.unassociate",
  "cloudprofiler.profiles.create",
  "cloudprofiler.profiles.list",
  "cloudprofiler.profiles.update",
  "cloudscheduler.jobs.create",
  "cloudscheduler.jobs.delete",
  "cloudscheduler.jobs.enable",
  "cloudscheduler.jobs.fullView",
  "cloudscheduler.jobs.get",
  "cloudscheduler.jobs.list",
  "cloudscheduler.jobs.pause",
  "cloudscheduler.jobs.run",
  "cloudscheduler.jobs.update",
  "cloudsecurityscanner.crawledurls.list",
  "cloudsecurityscanner.results.get",
  "cloudsecurityscanner.results.list",
  "cloudsecurityscanner.scanruns.get",
  "cloudsecurityscanner.scanruns.getSummary",
  "cloudsecurityscanner.scanruns.list",
  "cloudsecurityscanner.scanruns.stop",
  "cloudsecurityscanner.scans.create",
  "cloudsecurityscanner.scans.delete",
  "cloudsecurityscanner.scans.get",
  "cloudsecurityscanner.scans.list",
  "cloudsecurityscanner.scans.run",
  "cloudsecurityscanner.scans.update",
  "cloudsql.backupRuns.create",
  "cloudsql.backupRuns.delete",
  "cloudsql.backupRuns.get",
  "cloudsql.backupRuns.list",
  "cloudsql.databases.create",
  "cloudsql.databases.delete",
  "cloudsql.databases.get",
  "cloudsql.databases.list",
  "cloudsql.databases.update",
  "cloudsql.instances.clone",
  "cloudsql.instances.connect",
  "cloudsql.instances.create",
  "cloudsql.instances.delete",
  "cloudsql.instances.demoteMaster",
  "cloudsql.instances.export",
  "cloudsql.instances.failover",
  "cloudsql.instances.get",
  "cloudsql.instances.import",
  "cloudsql.instances.list",
  "cloudsql.instances.promoteReplica",
  "cloudsql.instances.resetSslConfig",
  "cloudsql.instances.restart",
  "cloudsql.instances.restoreBackup",
  "cloudsql.instances.startReplica",
  "cloudsql.instances.stopReplica",
  "cloudsql.instances.truncateLog",
  "cloudsql.instances.update",
  "cloudsql.sslCerts.create",
  "cloudsql.sslCerts.createEphemeral",
  "cloudsql.sslCerts.delete",
  "cloudsql.sslCerts.get",
  "cloudsql.sslCerts.list",
  "cloudsql.users.create",
  "cloudsql.users.delete",
  "cloudsql.users.list",
  "cloudsql.users.update",
  "cloudsupport.accounts.get",
  "cloudsupport.accounts.getIamPolicy",
  "cloudsupport.accounts.getUserRoles",
  "cloudsupport.accounts.list",
  "cloudsupport.accounts.update",
  "cloudsupport.accounts.updateUserRoles",
  "cloudsupport.operations.get",
  "cloudtasks.locations.get",
  "cloudtasks.locations.list",
  "cloudtasks.queues.create",
  "cloudtasks.queues.delete",
  "cloudtasks.queues.get",
  "cloudtasks.queues.list",
  "cloudtasks.queues.pause",
  "cloudtasks.queues.purge",
  "cloudtasks.queues.resume",
  "cloudtasks.queues.update",
  "cloudtasks.tasks.create",
  "cloudtasks.tasks.delete",
  "cloudtasks.tasks.fullView",
  "cloudtasks.tasks.get",
  "cloudtasks.tasks.list",
  "cloudtasks.tasks.run",
  "cloudtestservice.environmentcatalog.get",
  "cloudtestservice.matrices.create",
  "cloudtestservice.matrices.delete",
  "cloudtestservice.matrices.get",
  "cloudtestservice.matrices.update",
  "cloudtoolresults.executions.create",
  "cloudtoolresults.executions.get",
  "cloudtoolresults.executions.list",
  "cloudtoolresults.executions.update",
  "cloudtoolresults.histories.create",
  "cloudtoolresults.histories.get",
  "cloudtoolresults.histories.list",
  "cloudtoolresults.settings.create",
  "cloudtoolresults.settings.get",
  "cloudtoolresults.settings.update",
  "cloudtoolresults.steps.create",
  "cloudtoolresults.steps.get",
  "cloudtoolresults.steps.list",
  "cloudtoolresults.steps.update",
  "cloudtrace.insights.get",
  "cloudtrace.insights.list",
  "cloudtrace.stats.get",
  "cloudtrace.tasks.create",
  "cloudtrace.tasks.delete",
  "cloudtrace.tasks.get",
  "cloudtrace.tasks.list",
  "cloudtrace.traces.get",
  "cloudtrace.traces.list",
  "cloudtrace.traces.patch",
  "composer.environments.create",
  "composer.environments.delete",
  "composer.environments.get",
  "composer.environments.list",
  "composer.environments.update",
  "composer.operations.delete",
  "composer.operations.get",
  "composer.operations.list",
  "compute.acceleratorTypes.get",
  "compute.acceleratorTypes.list",
  "compute.addresses.create",
  "compute.addresses.createInternal",
  "compute.addresses.delete",
  "compute.addresses.deleteInternal",
  "compute.addresses.get",
  "compute.addresses.list",
  "compute.addresses.setLabels",
  "compute.addresses.use",
  "compute.addresses.useInternal",
  "compute.autoscalers.create",
  "compute.autoscalers.delete",
  "compute.autoscalers.get",
  "compute.autoscalers.list",
  "compute.autoscalers.update",
  "compute.backendBuckets.create",
  "compute.backendBuckets.delete",
  "compute.backendBuckets.get",
  "compute.backendBuckets.list",
  "compute.backendBuckets.update",
  "compute.backendBuckets.use",
  "compute.backendServices.create",
  "compute.backendServices.delete",
  "compute.backendServices.get",
  "compute.backendServices.list",
  "compute.backendServices.setSecurityPolicy",
  "compute.backendServices.update",
  "compute.backendServices.use",
  "compute.commitments.create",
  "compute.commitments.get",
  "compute.commitments.list",
  "compute.diskTypes.get",
  "compute.diskTypes.list",
  "compute.disks.create",
  "compute.disks.createSnapshot",
  "compute.disks.delete",
  "compute.disks.get",
  "compute.disks.getIamPolicy",
  "compute.disks.list",
  "compute.disks.resize",
  "compute.disks.setLabels",
  "compute.disks.update",
  "compute.disks.use",
  "compute.disks.useReadOnly",
  "compute.firewalls.create",
  "compute.firewalls.delete",
  "compute.firewalls.get",
  "compute.firewalls.list",
  "compute.firewalls.update",
  "compute.forwardingRules.create",
  "compute.forwardingRules.delete",
  "compute.forwardingRules.get",
  "compute.forwardingRules.list",
  "compute.forwardingRules.setLabels",
  "compute.forwardingRules.setTarget",
  "compute.globalAddresses.create",
  "compute.globalAddresses.createInternal",
  "compute.globalAddresses.delete",
  "compute.globalAddresses.deleteInternal",
  "compute.globalAddresses.get",
  "compute.globalAddresses.list",
  "compute.globalAddresses.setLabels",
  "compute.globalAddresses.use",
  "compute.globalForwardingRules.create",
  "compute.globalForwardingRules.delete",
  "compute.globalForwardingRules.get",
  "compute.globalForwardingRules.list",
  "compute.globalForwardingRules.setLabels",
  "compute.globalForwardingRules.setTarget",
  "compute.globalOperations.delete",
  "compute.globalOperations.get",
  "compute.globalOperations.getIamPolicy",
  "compute.globalOperations.list",
  "compute.healthChecks.create",
  "compute.healthChecks.delete",
  "compute.healthChecks.get",
  "compute.healthChecks.list",
  "compute.healthChecks.update",
  "compute.healthChecks.use",
  "compute.healthChecks.useReadOnly",
  "compute.httpHealthChecks.create",
  "compute.httpHealthChecks.delete",
  "compute.httpHealthChecks.get",
  "compute.httpHealthChecks.list",
  "compute.httpHealthChecks.update",
  "compute.httpHealthChecks.use",
  "compute.httpHealthChecks.useReadOnly",
  "compute.httpsHealthChecks.create",
  "compute.httpsHealthChecks.delete",
  "compute.httpsHealthChecks.get",
  "compute.httpsHealthChecks.list",
  "compute.httpsHealthChecks.update",
  "compute.httpsHealthChecks.use",
  "compute.httpsHealthChecks.useReadOnly",
  "compute.images.create",
  "compute.images.delete",
  "compute.images.deprecate",
  "compute.images.get",
  "compute.images.getFromFamily",
  "compute.images.getIamPolicy",
  "compute.images.list",
  "compute.images.setLabels",
  "compute.images.update",
  "compute.images.useReadOnly",
  "compute.instanceGroupManagers.create",
  "compute.instanceGroupManagers.delete",
  "compute.instanceGroupManagers.get",
  "compute.instanceGroupManagers.list",
  "compute.instanceGroupManagers.update",
  "compute.instanceGroupManagers.use",
  "compute.instanceGroups.create",
  "compute.instanceGroups.delete",
  "compute.instanceGroups.get",
  "compute.instanceGroups.list",
  "compute.instanceGroups.update",
  "compute.instanceGroups.use",
  "compute.instanceTemplates.create",
  "compute.instanceTemplates.delete",
  "compute.instanceTemplates.get",
  "compute.instanceTemplates.getIamPolicy",
  "compute.instanceTemplates.list",
  "compute.instanceTemplates.useReadOnly",
  "compute.instances.addAccessConfig",
  "compute.instances.addMaintenancePolicies",
  "compute.instances.attachDisk",
  "compute.instances.create",
  "compute.instances.delete",
  "compute.instances.deleteAccessConfig",
  "compute.instances.detachDisk",
  "compute.instances.get",
  "compute.instances.getGuestAttributes",
  "compute.instances.getIamPolicy",
  "compute.instances.getSerialPortOutput",
  "compute.instances.list",
  "compute.instances.listReferrers",
  "compute.instances.osAdminLogin",
  "compute.instances.osLogin",
  "compute.instances.removeMaintenancePolicies",
  "compute.instances.reset",
  "compute.instances.resume",
  "compute.instances.setDeletionProtection",
  "compute.instances.setDiskAutoDelete",
  "compute.instances.setLabels",
  "compute.instances.setMachineResources",
  "compute.instances.setMachineType",
  "compute.instances.setMetadata",
  "compute.instances.setMinCpuPlatform",
  "compute.instances.setScheduling",
  "compute.instances.setServiceAccount",
  "compute.instances.setShieldedVmIntegrityPolicy",
  "compute.instances.setTags",
  "compute.instances.start",
  "compute.instances.startWithEncryptionKey",
  "compute.instances.stop",
  "compute.instances.suspend",
  "compute.instances.update",
  "compute.instances.updateAccessConfig",
  "compute.instances.updateNetworkInterface",
  "compute.instances.updateShieldedVmConfig",
  "compute.instances.use",
  "compute.interconnectAttachments.create",
  "compute.interconnectAttachments.delete",
  "compute.interconnectAttachments.get",
  "compute.interconnectAttachments.list",
  "compute.interconnectAttachments.setLabels",
  "compute.interconnectAttachments.update",
  "compute.interconnectAttachments.use",
  "compute.interconnectLocations.get",
  "compute.interconnectLocations.list",
  "compute.interconnects.create",
  "compute.interconnects.delete",
  "compute.interconnects.get",
  "compute.interconnects.list",
  "compute.interconnects.setLabels",
  "compute.interconnects.update",
  "compute.interconnects.use",
  "compute.licenseCodes.get",
  "compute.licenseCodes.getIamPolicy",
  "compute.licenseCodes.list",
  "compute.licenseCodes.update",
  "compute.licenseCodes.use",
  "compute.licenses.create",
  "compute.licenses.delete",
  "compute.licenses.get",
  "compute.licenses.getIamPolicy",
  "compute.licenses.list",
  "compute.machineTypes.get",
  "compute.machineTypes.list",
  "compute.maintenancePolicies.create",
  "compute.maintenancePolicies.delete",
  "compute.maintenancePolicies.get",
  "compute.maintenancePolicies.getIamPolicy",
  "compute.maintenancePolicies.list",
  "compute.maintenancePolicies.use",
  "compute.networks.addPeering",
  "compute.networks.create",
  "compute.networks.delete",
  "compute.networks.get",
  "compute.networks.list",
  "compute.networks.removePeering",
  "compute.networks.switchToCustomMode",
  "compute.networks.update",
  "compute.networks.updatePeering",
  "compute.networks.updatePolicy",
  "compute.networks.use",
  "compute.networks.useExternalIp",
  "compute.nodeGroups.addNodes",
  "compute.nodeGroups.create",
  "compute.nodeGroups.delete",
  "compute.nodeGroups.deleteNodes",
  "compute.nodeGroups.get",
  "compute.nodeGroups.getIamPolicy",
  "compute.nodeGroups.list",
  "compute.nodeGroups.setNodeTemplate",
  "compute.nodeTemplates.create",
  "compute.nodeTemplates.delete",
  "compute.nodeTemplates.get",
  "compute.nodeTemplates.getIamPolicy",
  "compute.nodeTemplates.list",
  "compute.nodeTypes.get",
  "compute.nodeTypes.list",
  "compute.projects.get",
  "compute.projects.setCommonInstanceMetadata",
  "compute.projects.setDefaultNetworkTier",
  "compute.projects.setDefaultServiceAccount",
  "compute.projects.setUsageExportBucket",
  "compute.regionBackendServices.create",
  "compute.regionBackendServices.delete",
  "compute.regionBackendServices.get",
  "compute.regionBackendServices.list",
  "compute.regionBackendServices.setSecurityPolicy",
  "compute.regionBackendServices.update",
  "compute.regionBackendServices.use",
  "compute.regionOperations.delete",
  "compute.regionOperations.get",
  "compute.regionOperations.getIamPolicy",
  "compute.regionOperations.list",
  "compute.regions.get",
  "compute.regions.list",
  "compute.routers.create",
  "compute.routers.delete",
  "compute.routers.get",
  "compute.routers.list",
  "compute.routers.update",
  "compute.routers.use",
  "compute.routes.create",
  "compute.routes.delete",
  "compute.routes.get",
  "compute.routes.list",
  "compute.securityPolicies.create",
  "compute.securityPolicies.delete",
  "compute.securityPolicies.get",
  "compute.securityPolicies.getIamPolicy",
  "compute.securityPolicies.list",
  "compute.securityPolicies.update",
  "compute.securityPolicies.use",
  "compute.snapshots.create",
  "compute.snapshots.delete",
  "compute.snapshots.get",
  "compute.snapshots.getIamPolicy",
  "compute.snapshots.list",
  "compute.snapshots.setLabels",
  "compute.snapshots.useReadOnly",
  "compute.sslCertificates.create",
  "compute.sslCertificates.delete",
  "compute.sslCertificates.get",
  "compute.sslCertificates.list",
  "compute.sslPolicies.create",
  "compute.sslPolicies.delete",
  "compute.sslPolicies.get",
  "compute.sslPolicies.list",
  "compute.sslPolicies.listAvailableFeatures",
  "compute.sslPolicies.update",
  "compute.sslPolicies.use",
  "compute.subnetworks.create",
  "compute.subnetworks.delete",
  "compute.subnetworks.expandIpCidrRange",
  "compute.subnetworks.get",
  "compute.subnetworks.getIamPolicy",
  "compute.subnetworks.list",
  "compute.subnetworks.setPrivateIpGoogleAccess",
  "compute.subnetworks.update",
  "compute.subnetworks.use",
  "compute.subnetworks.useExternalIp",
  "compute.targetHttpProxies.create",
  "compute.targetHttpProxies.delete",
  "compute.targetHttpProxies.get",
  "compute.targetHttpProxies.list",
  "compute.targetHttpProxies.setUrlMap",
  "compute.targetHttpProxies.use",
  "compute.targetHttpsProxies.create",
  "compute.targetHttpsProxies.delete",
  "compute.targetHttpsProxies.get",
  "compute.targetHttpsProxies.list",
  "compute.targetHttpsProxies.setSslCertificates",
  "compute.targetHttpsProxies.setSslPolicy",
  "compute.targetHttpsProxies.setUrlMap",
  "compute.targetHttpsProxies.use",
  "compute.targetInstances.create",
  "compute.targetInstances.delete",
  "compute.targetInstances.get",
  "compute.targetInstances.list",
  "compute.targetInstances.use",
  "compute.targetPools.addHealthCheck",
  "compute.targetPools.addInstance",
  "compute.targetPools.create",
  "compute.targetPools.delete",
  "compute.targetPools.get",
  "compute.targetPools.list",
  "compute.targetPools.removeHealthCheck",
  "compute.targetPools.removeInstance",
  "compute.targetPools.update",
  "compute.targetPools.use",
  "compute.targetSslProxies.create",
  "compute.targetSslProxies.delete",
  "compute.targetSslProxies.get",
  "compute.targetSslProxies.list",
  "compute.targetSslProxies.setBackendService",
  "compute.targetSslProxies.setProxyHeader",
  "compute.targetSslProxies.setSslCertificates",
  "compute.targetSslProxies.use",
  "compute.targetTcpProxies.create",
  "compute.targetTcpProxies.delete",
  "compute.targetTcpProxies.get",
  "compute.targetTcpProxies.list",
  "compute.targetTcpProxies.update",
  "compute.targetTcpProxies.use",
  "compute.targetVpnGateways.create",
  "compute.targetVpnGateways.delete",
  "compute.targetVpnGateways.get",
  "compute.targetVpnGateways.list",
  "compute.targetVpnGateways.setLabels",
  "compute.targetVpnGateways.use",
  "compute.urlMaps.create",
  "compute.urlMaps.delete",
  "compute.urlMaps.get",
  "compute.urlMaps.invalidateCache",
  "compute.urlMaps.list",
  "compute.urlMaps.update",
  "compute.urlMaps.use",
  "compute.urlMaps.validate",
  "compute.vpnTunnels.create",
  "compute.vpnTunnels.delete",
  "compute.vpnTunnels.get",
  "compute.vpnTunnels.list",
  "compute.vpnTunnels.setLabels",
  "compute.zoneOperations.delete",
  "compute.zoneOperations.get",
  "compute.zoneOperations.getIamPolicy",
  "compute.zoneOperations.list",
  "compute.zones.get",
  "compute.zones.list",
  "container.apiServices.create",
  "container.apiServices.delete",
  "container.apiServices.get",
  "container.apiServices.list",
  "container.apiServices.update",
  "container.apiServices.updateStatus",
  "container.backendConfigs.create",
  "container.backendConfigs.delete",
  "container.backendConfigs.get",
  "container.backendConfigs.list",
  "container.backendConfigs.update",
  "container.bindings.create",
  "container.bindings.delete",
  "container.bindings.get",
  "container.bindings.list",
  "container.bindings.update",
  "container.certificateSigningRequests.create",
  "container.certificateSigningRequests.delete",
  "container.certificateSigningRequests.get",
  "container.certificateSigningRequests.list",
  "container.certificateSigningRequests.update",
  "container.certificateSigningRequests.updateStatus",
  "container.clusterRoleBindings.get",
  "container.clusterRoleBindings.list",
  "container.clusterRoles.get",
  "container.clusterRoles.list",
  "container.clusters.create",
  "container.clusters.delete",
  "container.clusters.get",
  "container.clusters.getCredentials",
  "container.clusters.list",
  "container.clusters.update",
  "container.componentStatuses.get",
  "container.componentStatuses.list",
  "container.configMaps.create",
  "container.configMaps.delete",
  "container.configMaps.get",
  "container.configMaps.list",
  "container.configMaps.update",
  "container.controllerRevisions.create",
  "container.controllerRevisions.delete",
  "container.controllerRevisions.get",
  "container.controllerRevisions.list",
  "container.controllerRevisions.update",
  "container.cronJobs.create",
  "container.cronJobs.delete",
  "container.cronJobs.get",
  "container.cronJobs.getStatus",
  "container.cronJobs.list",
  "container.cronJobs.update",
  "container.cronJobs.updateStatus",
  "container.customResourceDefinitions.create",
  "container.customResourceDefinitions.delete",
  "container.customResourceDefinitions.get",
  "container.customResourceDefinitions.list",
  "container.customResourceDefinitions.update",
  "container.customResourceDefinitions.updateStatus",
  "container.daemonSets.create",
  "container.daemonSets.delete",
  "container.daemonSets.get",
  "container.daemonSets.getStatus",
  "container.daemonSets.list",
  "container.daemonSets.update",
  "container.daemonSets.updateStatus",
  "container.deployments.create",
  "container.deployments.delete",
  "container.deployments.get",
  "container.deployments.getScale",
  "container.deployments.getStatus",
  "container.deployments.list",
  "container.deployments.rollback",
  "container.deployments.update",
  "container.deployments.updateScale",
  "container.deployments.updateStatus",
  "container.endpoints.create",
  "container.endpoints.delete",
  "container.endpoints.get",
  "container.endpoints.list",
  "container.endpoints.update",
  "container.events.create",
  "container.events.delete",
  "container.events.get",
  "container.events.list",
  "container.events.update",
  "container.horizontalPodAutoscalers.create",
  "container.horizontalPodAutoscalers.delete",
  "container.horizontalPodAutoscalers.get",
  "container.horizontalPodAutoscalers.getStatus",
  "container.horizontalPodAutoscalers.list",
  "container.horizontalPodAutoscalers.update",
  "container.horizontalPodAutoscalers.updateStatus",
  "container.ingresses.create",
  "container.ingresses.delete",
  "container.ingresses.get",
  "container.ingresses.getStatus",
  "container.ingresses.list",
  "container.ingresses.update",
  "container.ingresses.updateStatus",
  "container.initializerConfigurations.create",
  "container.initializerConfigurations.delete",
  "container.initializerConfigurations.get",
  "container.initializerConfigurations.list",
  "container.initializerConfigurations.update",
  "container.jobs.create",
  "container.jobs.delete",
  "container.jobs.get",
  "container.jobs.getStatus",
  "container.jobs.list",
  "container.jobs.update",
  "container.jobs.updateStatus",
  "container.limitRanges.create",
  "container.limitRanges.delete",
  "container.limitRanges.get",
  "container.limitRanges.list",
  "container.limitRanges.update",
  "container.localSubjectAccessReviews.list",
  "container.namespaces.create",
  "container.namespaces.delete",
  "container.namespaces.get",
  "container.namespaces.getStatus",
  "container.namespaces.list",
  "container.namespaces.update",
  "container.namespaces.updateStatus",
  "container.networkPolicies.create",
  "container.networkPolicies.delete",
  "container.networkPolicies.get",
  "container.networkPolicies.list",
  "container.networkPolicies.update",
  "container.nodes.create",
  "container.nodes.delete",
  "container.nodes.get",
  "container.nodes.getStatus",
  "container.nodes.list",
  "container.nodes.proxy",
  "container.nodes.update",
  "container.nodes.updateStatus",
  "container.operations.get",
  "container.operations.list",
  "container.persistentVolumeClaims.create",
  "container.persistentVolumeClaims.delete",
  "container.persistentVolumeClaims.get",
  "container.persistentVolumeClaims.getStatus",
  "container.persistentVolumeClaims.list",
  "container.persistentVolumeClaims.update",
  "container.persistentVolumeClaims.updateStatus",
  "container.persistentVolumes.create",
  "container.persistentVolumes.delete",
  "container.persistentVolumes.get",
  "container.persistentVolumes.getStatus",
  "container.persistentVolumes.list",
  "container.persistentVolumes.update",
  "container.persistentVolumes.updateStatus",
  "container.petSets.create",
  "container.petSets.delete",
  "container.petSets.get",
  "container.petSets.list",
  "container.petSets.update",
  "container.petSets.updateStatus",
  "container.podDisruptionBudgets.create",
  "container.podDisruptionBudgets.delete",
  "container.podDisruptionBudgets.get",
  "container.podDisruptionBudgets.getStatus",
  "container.podDisruptionBudgets.list",
  "container.podDisruptionBudgets.update",
  "container.podDisruptionBudgets.updateStatus",
  "container.podPresets.create",
  "container.podPresets.delete",
  "container.podPresets.get",
  "container.podPresets.list",
  "container.podPresets.update",
  "container.podSecurityPolicies.create",
  "container.podSecurityPolicies.delete",
  "container.podSecurityPolicies.get",
  "container.podSecurityPolicies.list",
  "container.podSecurityPolicies.update",
  "container.podSecurityPolicies.use",
  "container.podTemplates.create",
  "container.podTemplates.delete",
  "container.podTemplates.get",
  "container.podTemplates.list",
  "container.podTemplates.update",
  "container.pods.attach",
  "container.pods.create",
  "container.pods.delete",
  "container.pods.evict",
  "container.pods.exec",
  "container.pods.get",
  "container.pods.getLogs",
  "container.pods.getStatus",
  "container.pods.initialize",
  "container.pods.list",
  "container.pods.portForward",
  "container.pods.proxy",
  "container.pods.update",
  "container.pods.updateStatus",
  "container.replicaSets.create",
  "container.replicaSets.delete",
  "container.replicaSets.get",
  "container.replicaSets.getScale",
  "container.replicaSets.getStatus",
  "container.replicaSets.list",
  "container.replicaSets.update",
  "container.replicaSets.updateScale",
  "container.replicaSets.updateStatus",
  "container.replicationControllers.create",
  "container.replicationControllers.delete",
  "container.replicationControllers.get",
  "container.replicationControllers.getScale",
  "container.replicationControllers.getStatus",
  "container.replicationControllers.list",
  "container.replicationControllers.update",
  "container.replicationControllers.updateScale",
  "container.replicationControllers.updateStatus",
  "container.resourceQuotas.create",
  "container.resourceQuotas.delete",
  "container.resourceQuotas.get",
  "container.resourceQuotas.getStatus",
  "container.resourceQuotas.list",
  "container.resourceQuotas.update",
  "container.resourceQuotas.updateStatus",
  "container.roleBindings.get",
  "container.roleBindings.list",
  "container.roles.get",
  "container.roles.list",
  "container.scheduledJobs.create",
  "container.scheduledJobs.delete",
  "container.scheduledJobs.get",
  "container.scheduledJobs.list",
  "container.scheduledJobs.update",
  "container.scheduledJobs.updateStatus",
  "container.secrets.create",
  "container.secrets.delete",
  "container.secrets.get",
  "container.secrets.list",
  "container.secrets.update",
  "container.selfSubjectAccessReviews.create",
  "container.selfSubjectAccessReviews.list",
  "container.serviceAccounts.create",
  "container.serviceAccounts.delete",
  "container.serviceAccounts.get",
  "container.serviceAccounts.list",
  "container.serviceAccounts.update",
  "container.services.create",
  "container.services.delete",
  "container.services.get",
  "container.services.getStatus",
  "container.services.list",
  "container.services.proxy",
  "container.services.update",
  "container.services.updateStatus",
  "container.statefulSets.create",
  "container.statefulSets.delete",
  "container.statefulSets.get",
  "container.statefulSets.getScale",
  "container.statefulSets.getStatus",
  "container.statefulSets.list",
  "container.statefulSets.update",
  "container.statefulSets.updateScale",
  "container.statefulSets.updateStatus",
  "container.storageClasses.create",
  "container.storageClasses.delete",
  "container.storageClasses.get",
  "container.storageClasses.list",
  "container.storageClasses.update",
  "container.subjectAccessReviews.list",
  "container.thirdPartyObjects.create",
  "container.thirdPartyObjects.delete",
  "container.thirdPartyObjects.get",
  "container.thirdPartyObjects.list",
  "container.thirdPartyObjects.update",
  "container.thirdPartyResources.create",
  "container.thirdPartyResources.delete",
  "container.thirdPartyResources.get",
  "container.thirdPartyResources.list",
  "container.thirdPartyResources.update",
  "container.tokenReviews.create",
  "dataflow.jobs.cancel",
  "dataflow.jobs.create",
  "dataflow.jobs.get",
  "dataflow.jobs.list",
  "dataflow.jobs.updateContents",
  "dataflow.messages.list",
  "dataflow.metrics.get",
  "dataprep.projects.use",
  "dataproc.agents.create",
  "dataproc.agents.delete",
  "dataproc.agents.get",
  "dataproc.agents.list",
  "dataproc.agents.update",
  "dataproc.clusters.create",
  "dataproc.clusters.delete",
  "dataproc.clusters.get",
  "dataproc.clusters.list",
  "dataproc.clusters.update",
  "dataproc.clusters.use",
  "dataproc.jobs.cancel",
  "dataproc.jobs.create",
  "dataproc.jobs.delete",
  "dataproc.jobs.get",
  "dataproc.jobs.list",
  "dataproc.jobs.update",
  "dataproc.operations.cancel",
  "dataproc.operations.delete",
  "dataproc.operations.get",
  "dataproc.operations.list",
  "dataproc.tasks.lease",
  "dataproc.tasks.listInvalidatedLeases",
  "dataproc.tasks.reportStatus",
  "dataproc.workflowTemplates.create",
  "dataproc.workflowTemplates.delete",
  "dataproc.workflowTemplates.get",
  "dataproc.workflowTemplates.getIamPolicy",
  "dataproc.workflowTemplates.instantiate",
  "dataproc.workflowTemplates.instantiateInline",
  "dataproc.workflowTemplates.list",
  "dataproc.workflowTemplates.update",
  "datastore.databases.get",
  "datastore.databases.getIamPolicy",
  "datastore.databases.list",
  "datastore.databases.update",
  "datastore.entities.allocateIds",
  "datastore.entities.create",
  "datastore.entities.delete",
  "datastore.entities.get",
  "datastore.entities.list",
  "datastore.entities.update",
  "datastore.indexes.create",
  "datastore.indexes.delete",
  "datastore.indexes.get",
  "datastore.indexes.list",
  "datastore.indexes.update",
  "datastore.namespaces.get",
  "datastore.namespaces.getIamPolicy",
  "datastore.namespaces.list",
  "datastore.statistics.get",
  "datastore.statistics.list",
  "deploymentmanager.compositeTypes.create",
  "deploymentmanager.compositeTypes.delete",
  "deploymentmanager.compositeTypes.get",
  "deploymentmanager.compositeTypes.list",
  "deploymentmanager.compositeTypes.update",
  "deploymentmanager.deployments.cancelPreview",
  "deploymentmanager.deployments.create",
  "deploymentmanager.deployments.delete",
  "deploymentmanager.deployments.get",
  "deploymentmanager.deployments.list",
  "deploymentmanager.deployments.stop",
  "deploymentmanager.deployments.update",
  "deploymentmanager.manifests.get",
  "deploymentmanager.manifests.list",
  "deploymentmanager.operations.get",
  "deploymentmanager.operations.list",
  "deploymentmanager.resources.get",
  "deploymentmanager.resources.list",
  "deploymentmanager.typeProviders.create",
  "deploymentmanager.typeProviders.delete",
  "deploymentmanager.typeProviders.get",
  "deploymentmanager.typeProviders.getType",
  "deploymentmanager.typeProviders.list",
  "deploymentmanager.typeProviders.listTypes",
  "deploymentmanager.typeProviders.update",
  "deploymentmanager.types.create",
  "deploymentmanager.types.delete",
  "deploymentmanager.types.get",
  "deploymentmanager.types.list",
  "deploymentmanager.types.update",
  "dialogflow.agents.export",
  "dialogflow.agents.get",
  "dialogflow.agents.import",
  "dialogflow.agents.restore",
  "dialogflow.agents.search",
  "dialogflow.agents.train",
  "dialogflow.contexts.create",
  "dialogflow.contexts.delete",
  "dialogflow.contexts.get",
  "dialogflow.contexts.list",
  "dialogflow.contexts.update",
  "dialogflow.entityTypes.create",
  "dialogflow.entityTypes.createEntity",
  "dialogflow.entityTypes.delete",
  "dialogflow.entityTypes.deleteEntity",
  "dialogflow.entityTypes.get",
  "dialogflow.entityTypes.list",
  "dialogflow.entityTypes.update",
  "dialogflow.entityTypes.updateEntity",
  "dialogflow.intents.create",
  "dialogflow.intents.delete",
  "dialogflow.intents.get",
  "dialogflow.intents.list",
  "dialogflow.intents.update",
  "dialogflow.operations.get",
  "dialogflow.sessionEntityTypes.create",
  "dialogflow.sessionEntityTypes.delete",
  "dialogflow.sessionEntityTypes.get",
  "dialogflow.sessionEntityTypes.list",
  "dialogflow.sessionEntityTypes.update",
  "dialogflow.sessions.detectIntent",
  "dialogflow.sessions.streamingDetectIntent",
  "dlp.analyzeRiskTemplates.create",
  "dlp.analyzeRiskTemplates.delete",
  "dlp.analyzeRiskTemplates.get",
  "dlp.analyzeRiskTemplates.list",
  "dlp.analyzeRiskTemplates.update",
  "dlp.deidentifyTemplates.create",
  "dlp.deidentifyTemplates.delete",
  "dlp.deidentifyTemplates.get",
  "dlp.deidentifyTemplates.list",
  "dlp.deidentifyTemplates.update",
  "dlp.inspectTemplates.create",
  "dlp.inspectTemplates.delete",
  "dlp.inspectTemplates.get",
  "dlp.inspectTemplates.list",
  "dlp.inspectTemplates.update",
  "dlp.jobTriggers.create",
  "dlp.jobTriggers.delete",
  "dlp.jobTriggers.get",
  "dlp.jobTriggers.list",
  "dlp.jobTriggers.update",
  "dlp.jobs.cancel",
  "dlp.jobs.delete",
  "dlp.storedInfoTypes.create",
  "dlp.storedInfoTypes.delete",
  "dlp.storedInfoTypes.get",
  "dlp.storedInfoTypes.list",
  "dlp.storedInfoTypes.update",
  "dns.changes.create",
  "dns.changes.get",
  "dns.changes.list",
  "dns.dnsKeys.get",
  "dns.dnsKeys.list",
  "dns.managedZoneOperations.get",
  "dns.managedZoneOperations.list",
  "dns.managedZones.create",
  "dns.managedZones.delete",
  "dns.managedZones.get",
  "dns.managedZones.list",
  "dns.managedZones.update",
  "dns.projects.get",
  "dns.resourceRecordSets.create",
  "dns.resourceRecordSets.delete",
  "dns.resourceRecordSets.list",
  "dns.resourceRecordSets.update",
  "endpoints.portals.attachCustomDomain",
  "endpoints.portals.detachCustomDomain",
  "endpoints.portals.listCustomDomains",
  "endpoints.portals.update",
  "errorreporting.applications.list",
  "errorreporting.errorEvents.create",
  "errorreporting.errorEvents.delete",
  "errorreporting.errorEvents.list",
  "errorreporting.groupMetadata.get",
  "errorreporting.groupMetadata.update",
  "errorreporting.groups.list",
  "file.instances.create",
  "file.instances.delete",
  "file.instances.get",
  "file.instances.list",
  "file.instances.update",
  "file.locations.get",
  "file.locations.list",
  "file.operations.cancel",
  "file.operations.delete",
  "file.operations.get",
  "file.operations.list",
  "firebase.billingPlans.get",
  "firebase.clients.create",
  "firebase.clients.delete",
  "firebase.clients.get",
  "firebase.links.list",
  "firebase.projects.get",
  "firebase.projects.update",
  "firebaseabt.experimentresults.get",
  "firebaseabt.experiments.create",
  "firebaseabt.experiments.delete",
  "firebaseabt.experiments.get",
  "firebaseabt.experiments.list",
  "firebaseabt.experiments.update",
  "firebaseabt.projectmetadata.get",
  "firebaseanalytics.resources.googleAnalyticsEdit",
  "firebaseanalytics.resources.googleAnalyticsReadAndAnalyze",
  "firebaseauth.configs.get",
  "firebaseauth.configs.update",
  "firebaseauth.users.create",
  "firebaseauth.users.createSession",
  "firebaseauth.users.delete",
  "firebaseauth.users.get",
  "firebaseauth.users.sendEmail",
  "firebaseauth.users.update",
  "firebasecrash.issues.update",
  "firebasecrash.reports.get",
  "firebasedatabase.instances.create",
  "firebasedatabase.instances.get",
  "firebasedatabase.instances.list",
  "firebasedatabase.instances.update",
  "firebasedynamiclinks.destinations.list",
  "firebasedynamiclinks.domains.create",
  "firebasedynamiclinks.domains.delete",
  "firebasedynamiclinks.domains.get",
  "firebasedynamiclinks.domains.list",
  "firebasedynamiclinks.domains.update",
  "firebasedynamiclinks.links.create",
  "firebasedynamiclinks.links.get",
  "firebasedynamiclinks.links.list",
  "firebasedynamiclinks.links.update",
  "firebasedynamiclinks.stats.get",
  "firebaseextensions.configs.list",
  "firebasehosting.sites.create",
  "firebasehosting.sites.delete",
  "firebasehosting.sites.get",
  "firebasehosting.sites.list",
  "firebasehosting.sites.update",
  "firebaseinappmessaging.campaigns.create",
  "firebaseinappmessaging.campaigns.delete",
  "firebaseinappmessaging.campaigns.get",
  "firebaseinappmessaging.campaigns.list",
  "firebaseinappmessaging.campaigns.update",
  "firebaseml.compressionjobs.create",
  "firebaseml.compressionjobs.delete",
  "firebaseml.compressionjobs.get",
  "firebaseml.compressionjobs.list",
  "firebaseml.compressionjobs.start",
  "firebaseml.compressionjobs.update",
  "firebaseml.models.create",
  "firebaseml.models.delete",
  "firebaseml.models.get",
  "firebaseml.models.list",
  "firebaseml.modelversions.create",
  "firebaseml.modelversions.get",
  "firebaseml.modelversions.list",
  "firebaseml.modelversions.update",
  "firebasenotifications.messages.create",
  "firebasenotifications.messages.delete",
  "firebasenotifications.messages.get",
  "firebasenotifications.messages.list",
  "firebasenotifications.messages.update",
  "firebaseperformance.config.create",
  "firebaseperformance.config.delete",
  "firebaseperformance.config.update",
  "firebaseperformance.data.get",
  "firebasepredictions.predictions.create",
  "firebasepredictions.predictions.delete",
  "firebasepredictions.predictions.list",
  "firebasepredictions.predictions.update",
  "firebaserules.releases.create",
  "firebaserules.releases.delete",
  "firebaserules.releases.get",
  "firebaserules.releases.getExecutable",
  "firebaserules.releases.list",
  "firebaserules.releases.update",
  "firebaserules.rulesets.create",
  "firebaserules.rulesets.delete",
  "firebaserules.rulesets.get",
  "firebaserules.rulesets.list",
  "firebaserules.rulesets.test",
  "genomics.datasets.create",
  "genomics.datasets.delete",
  "genomics.datasets.get",
  "genomics.datasets.list",
  "genomics.datasets.update",
  "genomics.operations.cancel",
  "genomics.operations.create",
  "genomics.operations.get",
  "genomics.operations.list",
  "iam.roles.get",
  "iam.roles.list",
  "iam.serviceAccountKeys.create",
  "iam.serviceAccountKeys.delete",
  "iam.serviceAccountKeys.get",
  "iam.serviceAccountKeys.list",
  "iam.serviceAccounts.actAs",
  "iam.serviceAccounts.create",
  "iam.serviceAccounts.delete",
  "iam.serviceAccounts.get",
  "iam.serviceAccounts.getIamPolicy",
  "iam.serviceAccounts.list",
  "iam.serviceAccounts.update",
  "logging.exclusions.get",
  "logging.exclusions.list",
  "logging.logEntries.create",
  "logging.logEntries.list",
  "logging.logMetrics.create",
  "logging.logMetrics.delete",
  "logging.logMetrics.get",
  "logging.logMetrics.list",
  "logging.logMetrics.update",
  "logging.logServiceIndexes.list",
  "logging.logServices.list",
  "logging.logs.delete",
  "logging.logs.list",
  "logging.sinks.get",
  "logging.sinks.list",
  "logging.usage.get",
  "ml.jobs.cancel",
  "ml.jobs.create",
  "ml.jobs.get",
  "ml.jobs.getIamPolicy",
  "ml.jobs.list",
  "ml.jobs.update",
  "ml.locations.get",
  "ml.locations.list",
  "ml.models.create",
  "ml.models.delete",
  "ml.models.get",
  "ml.models.getIamPolicy",
  "ml.models.list",
  "ml.models.predict",
  "ml.models.update",
  "ml.operations.cancel",
  "ml.operations.get",
  "ml.operations.list",
  "ml.projects.getConfig",
  "ml.versions.create",
  "ml.versions.delete",
  "ml.versions.get",
  "ml.versions.list",
  "ml.versions.predict",
  "ml.versions.update",
  "monitoring.alertPolicies.create",
  "monitoring.alertPolicies.delete",
  "monitoring.alertPolicies.get",
  "monitoring.alertPolicies.list",
  "monitoring.alertPolicies.update",
  "monitoring.dashboards.create",
  "monitoring.dashboards.delete",
  "monitoring.dashboards.get",
  "monitoring.dashboards.list",
  "monitoring.dashboards.update",
  "monitoring.groups.create",
  "monitoring.groups.delete",
  "monitoring.groups.get",
  "monitoring.groups.list",
  "monitoring.groups.update",
  "monitoring.metricDescriptors.create",
  "monitoring.metricDescriptors.delete",
  "monitoring.metricDescriptors.get",
  "monitoring.metricDescriptors.list",
  "monitoring.monitoredResourceDescriptors.get",
  "monitoring.monitoredResourceDescriptors.list",
  "monitoring.notificationChannelDescriptors.get",
  "monitoring.notificationChannelDescriptors.list",
  "monitoring.notificationChannels.create",
  "monitoring.notificationChannels.delete",
  "monitoring.notificationChannels.get",
  "monitoring.notificationChannels.list",
  "monitoring.notificationChannels.sendVerificationCode",
  "monitoring.notificationChannels.update",
  "monitoring.notificationChannels.verify",
  "monitoring.publicWidgets.create",
  "monitoring.publicWidgets.delete",
  "monitoring.publicWidgets.get",
  "monitoring.publicWidgets.list",
  "monitoring.publicWidgets.update",
  "monitoring.timeSeries.create",
  "monitoring.timeSeries.list",
  "monitoring.uptimeCheckConfigs.create",
  "monitoring.uptimeCheckConfigs.delete",
  "monitoring.uptimeCheckConfigs.get",
  "monitoring.uptimeCheckConfigs.list",
  "monitoring.uptimeCheckConfigs.update",
  "orgpolicy.policy.get",
  "proximitybeacon.attachments.create",
  "proximitybeacon.attachments.delete",
  "proximitybeacon.attachments.get",
  "proximitybeacon.attachments.list",
  "proximitybeacon.beacons.attach",
  "proximitybeacon.beacons.create",
  "proximitybeacon.beacons.get",
  "proximitybeacon.beacons.list",
  "proximitybeacon.beacons.update",
  "proximitybeacon.namespaces.create",
  "proximitybeacon.namespaces.delete",
  "proximitybeacon.namespaces.get",
  "proximitybeacon.namespaces.list",
  "proximitybeacon.namespaces.update",
  "pubsub.snapshots.create",
  "pubsub.snapshots.delete",
  "pubsub.snapshots.get",
  "pubsub.snapshots.list",
  "pubsub.snapshots.seek",
  "pubsub.snapshots.update",
  "pubsub.subscriptions.consume",
  "pubsub.subscriptions.create",
  "pubsub.subscriptions.delete",
  "pubsub.subscriptions.get",
  "pubsub.subscriptions.list",
  "pubsub.subscriptions.update",
  "pubsub.topics.attachSubscription",
  "pubsub.topics.create",
  "pubsub.topics.delete",
  "pubsub.topics.get",
  "pubsub.topics.list",
  "pubsub.topics.publish",
  "pubsub.topics.update",
  "redis.instances.create",
  "redis.instances.delete",
  "redis.instances.get",
  "redis.instances.list",
  "redis.instances.update",
  "redis.locations.get",
  "redis.locations.list",
  "redis.operations.cancel",
  "redis.operations.delete",
  "redis.operations.get",
  "redis.operations.list",
  "reservepartner.portal.read",
  "resourcemanager.projects.get",
  "resourcemanager.projects.getIamPolicy",
  "resourcemanager.projects.list",
  "resourcemanager.projects.move",
  "resourcemanager.projects.update",
  "runtimeconfig.configs.create",
  "runtimeconfig.configs.delete",
  "runtimeconfig.configs.get",
  "runtimeconfig.configs.list",
  "runtimeconfig.configs.update",
  "runtimeconfig.operations.get",
  "runtimeconfig.operations.list",
  "runtimeconfig.variables.create",
  "runtimeconfig.variables.delete",
  "runtimeconfig.variables.get",
  "runtimeconfig.variables.list",
  "runtimeconfig.variables.update",
  "runtimeconfig.variables.watch",
  "runtimeconfig.waiters.create",
  "runtimeconfig.waiters.delete",
  "runtimeconfig.waiters.get",
  "runtimeconfig.waiters.list",
  "runtimeconfig.waiters.update",
  "securitycenter.assets.get",
  "securitycenter.assets.getFieldNames",
  "securitycenter.assets.group",
  "securitycenter.assets.list",
  "securitycenter.assets.listAssetPropertyNames",
  "securitycenter.assets.runDiscovery",
  "securitycenter.assets.triggerDiscovery",
  "securitycenter.assets.update",
  "securitycenter.assetsecuritymarks.update",
  "securitycenter.configs.get",
  "securitycenter.configs.getIamPolicy",
  "securitycenter.configs.update",
  "securitycenter.findings.group",
  "securitycenter.findings.list",
  "securitycenter.findings.listFindingPropertyNames",
  "securitycenter.findings.setState",
  "securitycenter.findings.update",
  "securitycenter.findingsecuritymarks.update",
  "securitycenter.organizationsettings.get",
  "securitycenter.organizationsettings.update",
  "securitycenter.scans.get",
  "securitycenter.scans.list",
  "securitycenter.sources.get",
  "securitycenter.sources.getIamPolicy",
  "securitycenter.sources.list",
  "securitycenter.sources.update",
  "servicebroker.bindingoperations.get",
  "servicebroker.bindingoperations.list",
  "servicebroker.bindings.create",
  "servicebroker.bindings.delete",
  "servicebroker.bindings.get",
  "servicebroker.bindings.getIamPolicy",
  "servicebroker.bindings.list",
  "servicebroker.catalogs.create",
  "servicebroker.catalogs.delete",
  "servicebroker.catalogs.get",
  "servicebroker.catalogs.getIamPolicy",
  "servicebroker.catalogs.list",
  "servicebroker.instanceoperations.get",
  "servicebroker.instanceoperations.list",
  "servicebroker.instances.create",
  "servicebroker.instances.delete",
  "servicebroker.instances.get",
  "servicebroker.instances.getIamPolicy",
  "servicebroker.instances.list",
  "servicebroker.instances.update",
  "serviceconsumermanagement.consumers.get",
  "serviceconsumermanagement.quota.get",
  "serviceconsumermanagement.quota.update",
  "serviceconsumermanagement.tenancyu.addResource",
  "serviceconsumermanagement.tenancyu.create",
  "serviceconsumermanagement.tenancyu.delete",
  "serviceconsumermanagement.tenancyu.list",
  "serviceconsumermanagement.tenancyu.removeResource",
  "servicemanagement.consumerSettings.get",
  "servicemanagement.consumerSettings.list",
  "servicemanagement.consumerSettings.update",
  "servicemanagement.services.bind",
  "servicemanagement.services.check",
  "servicemanagement.services.create",
  "servicemanagement.services.delete",
  "servicemanagement.services.get",
  "servicemanagement.services.list",
  "servicemanagement.services.quota",
  "servicemanagement.services.report",
  "servicemanagement.services.update",
  "serviceusage.apiKeys.create",
  "serviceusage.apiKeys.delete",
  "serviceusage.apiKeys.get",
  "serviceusage.apiKeys.getProjectForKey",
  "serviceusage.apiKeys.list",
  "serviceusage.apiKeys.regenerate",
  "serviceusage.apiKeys.revert",
  "serviceusage.apiKeys.update",
  "serviceusage.operations.cancel",
  "serviceusage.operations.delete",
  "serviceusage.operations.get",
  "serviceusage.operations.list",
  "serviceusage.quotas.get",
  "serviceusage.quotas.update",
  "serviceusage.services.disable",
  "serviceusage.services.enable",
  "serviceusage.services.get",
  "serviceusage.services.list",
  "serviceusage.services.use",
  "source.repos.get",
  "source.repos.getIamPolicy",
  "source.repos.list",
  "source.repos.update",
  "spanner.databaseOperations.cancel",
  "spanner.databaseOperations.delete",
  "spanner.databaseOperations.get",
  "spanner.databaseOperations.list",
  "spanner.databases.beginOrRollbackReadWriteTransaction",
  "spanner.databases.beginReadOnlyTransaction",
  "spanner.databases.create",
  "spanner.databases.drop",
  "spanner.databases.get",
  "spanner.databases.getDdl",
  "spanner.databases.getIamPolicy",
  "spanner.databases.list",
  "spanner.databases.read",
  "spanner.databases.select",
  "spanner.databases.update",
  "spanner.databases.updateDdl",
  "spanner.databases.write",
  "spanner.instanceConfigs.get",
  "spanner.instanceConfigs.list",
  "spanner.instanceOperations.cancel",
  "spanner.instanceOperations.delete",
  "spanner.instanceOperations.get",
  "spanner.instanceOperations.list",
  "spanner.instances.create",
  "spanner.instances.delete",
  "spanner.instances.get",
  "spanner.instances.getIamPolicy",
  "spanner.instances.list",
  "spanner.instances.update",
  "spanner.sessions.create",
  "spanner.sessions.delete",
  "spanner.sessions.get",
  "spanner.sessions.list",
  "stackdriver.projects.get",
  "stackdriver.resourceMetadata.write",
  "storage.buckets.create",
  "storage.buckets.delete",
  "storage.buckets.list",
  "subscribewithgoogledeveloper.tools.get",
  "tpu.acceleratortypes.get",
  "tpu.acceleratortypes.list",
  "tpu.locations.get",
  "tpu.locations.list",
  "tpu.nodes.create",
  "tpu.nodes.delete",
  "tpu.nodes.get",
  "tpu.nodes.list",
  "tpu.nodes.reimage",
  "tpu.nodes.reset",
  "tpu.nodes.start",
  "tpu.nodes.stop",
  "tpu.operations.get",
  "tpu.operations.list",
  "tpu.tensorflowversions.get",
  "tpu.tensorflowversions.list"
 ],
 "stage": "GA",
 "etag": "AA=="
},
{
 "name": "roles/iam.serviceAccountKeyAdmin",
 "title": "Service Account Key Admin",
 "description": "Create and manage (and rotate) service account keys.",
 "includedPermissions": [
  "iam.serviceAccountKeys.create",
  "iam.serviceAccountKeys.delete",
  "iam.serviceAccountKeys.get",
  "iam.serviceAccountKeys.list",
  "iam.serviceAccounts.get",
  "iam.serviceAccounts.list",
  "resourcemanager.projects.get",
  "resourcemanager.projects.list"
 ],
 "stage": "GA",
 "etag": "AA=="
},
{
 "name": "roles/logging.viewer",
 "title": "Logs Viewer",
 "description": "Access to view logs, except for logs with private contents.",
 "includedPermissions": [
  "logging.exclusions.get",
  "logging.exclusions.list",
  "logging.logEntries.list",
  "logging.logMetrics.get",
  "logging.logMetrics.list",
  "logging.logServiceIndexes.list",
  "logging.logServices.list",
  "logging.logs.list",
  "logging.sinks.get",
  "logging.sinks.list",
  "logging.usage.get",
  "resourcemanager.projects.get"
 ],
 "stage": "GA",
 "etag": "AA=="
},
{
 "name": "roles/owner",
 "title": "Owner",
 "description": "Full access to all resources.",
 "includedPermissions": [
  "accesscontextmanager.accessLevels.create",
  "accesscontextmanager.accessLevels.delete",
  "accesscontextmanager.accessLevels.get",
  "accesscontextmanager.accessLevels.list",
  "accesscontextmanager.accessLevels.update",
  "accesscontextmanager.accessPolicies.create",
  "accesscontextmanager.accessPolicies.delete",
  "accesscontextmanager.accessPolicies.get",
  "accesscontextmanager.accessPolicies.getIamPolicy",
  "accesscontextmanager.accessPolicies.list",
  "accesscontextmanager.accessPolicies.setIamPolicy",
  "accesscontextmanager.accessPolicies.update",
  "accesscontextmanager.accessZones.create",
  "accesscontextmanager.accessZones.delete",
  "accesscontextmanager.accessZones.get",
  "accesscontextmanager.accessZones.list",
  "accesscontextmanager.accessZones.update",
  "accesscontextmanager.policies.create",
  "accesscontextmanager.policies.delete",
  "accesscontextmanager.policies.get",
  "accesscontextmanager.policies.getIamPolicy",
  "accesscontextmanager.policies.list",
  "accesscontextmanager.policies.setIamPolicy",
  "accesscontextmanager.policies.update",
  "accesscontextmanager.servicePerimeters.create",
  "accesscontextmanager.servicePerimeters.delete",
  "accesscontextmanager.servicePerimeters.get",
  "accesscontextmanager.servicePerimeters.list",
  "accesscontextmanager.servicePerimeters.update",
  "androidmanagement.enterprises.manage",
  "appengine.applications.create",
  "appengine.applications.get",
  "appengine.applications.update",
  "appengine.instances.delete",
  "appengine.instances.get",
  "appengine.instances.list",
  "appengine.memcache.addKey",
  "appengine.memcache.flush",
  "appengine.memcache.get",
  "appengine.memcache.getKey",
  "appengine.memcache.list",
  "appengine.memcache.update",
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
  "appengine.versions.getFileContents",
  "appengine.versions.list",
  "appengine.versions.update",
  "automl.annotationSpecs.create",
  "automl.annotationSpecs.delete",
  "automl.annotationSpecs.get",
  "automl.annotationSpecs.list",
  "automl.annotationSpecs.update",
  "automl.annotations.approve",
  "automl.annotations.create",
  "automl.annotations.list",
  "automl.annotations.manipulate",
  "automl.annotations.reject",
  "automl.datasets.create",
  "automl.datasets.delete",
  "automl.datasets.export",
  "automl.datasets.get",
  "automl.datasets.getIamPolicy",
  "automl.datasets.import",
  "automl.datasets.list",
  "automl.datasets.setIamPolicy",
  "automl.examples.delete",
  "automl.examples.get",
  "automl.examples.list",
  "automl.humanAnnotationTasks.create",
  "automl.humanAnnotationTasks.delete",
  "automl.humanAnnotationTasks.get",
  "automl.humanAnnotationTasks.list",
  "automl.locations.get",
  "automl.locations.getIamPolicy",
  "automl.locations.list",
  "automl.locations.setIamPolicy",
  "automl.modelEvaluations.create",
  "automl.modelEvaluations.get",
  "automl.modelEvaluations.list",
  "automl.models.create",
  "automl.models.delete",
  "automl.models.deploy",
  "automl.models.get",
  "automl.models.getIamPolicy",
  "automl.models.list",
  "automl.models.predict",
  "automl.models.setIamPolicy",
  "automl.models.undeploy",
  "automl.operations.cancel",
  "automl.operations.delete",
  "automl.operations.get",
  "automl.operations.list",
  "bigquery.config.get",
  "bigquery.config.update",
  "bigquery.datasets.create",
  "bigquery.datasets.delete",
  "bigquery.datasets.get",
  "bigquery.datasets.getIamPolicy",
  "bigquery.datasets.setIamPolicy",
  "bigquery.datasets.update",
  "bigquery.jobs.create",
  "bigquery.jobs.get",
  "bigquery.jobs.list",
  "bigquery.jobs.listAll",
  "bigquery.jobs.update",
  "bigquery.readsessions.create",
  "bigquery.savedqueries.create",
  "bigquery.savedqueries.delete",
  "bigquery.savedqueries.get",
  "bigquery.savedqueries.list",
  "bigquery.savedqueries.update",
  "bigquery.transfers.get",
  "bigquery.transfers.update",
  "bigtable.appProfiles.create",
  "bigtable.appProfiles.delete",
  "bigtable.appProfiles.get",
  "bigtable.appProfiles.list",
  "bigtable.appProfiles.update",
  "bigtable.clusters.create",
  "bigtable.clusters.delete",
  "bigtable.clusters.get",
  "bigtable.clusters.list",
  "bigtable.clusters.update",
  "bigtable.instances.create",
  "bigtable.instances.delete",
  "bigtable.instances.get",
  "bigtable.instances.getIamPolicy",
  "bigtable.instances.list",
  "bigtable.instances.setIamPolicy",
  "bigtable.instances.update",
  "bigtable.tables.checkConsistency",
  "bigtable.tables.create",
  "bigtable.tables.delete",
  "bigtable.tables.generateConsistencyToken",
  "bigtable.tables.get",
  "bigtable.tables.list",
  "bigtable.tables.mutateRows",
  "bigtable.tables.readRows",
  "bigtable.tables.sampleRowKeys",
  "bigtable.tables.update",
  "billing.resourceCosts.get",
  "binaryauthorization.attestors.create",
  "binaryauthorization.attestors.delete",
  "binaryauthorization.attestors.get",
  "binaryauthorization.attestors.getIamPolicy",
  "binaryauthorization.attestors.list",
  "binaryauthorization.attestors.setIamPolicy",
  "binaryauthorization.attestors.update",
  "binaryauthorization.attestors.verifyImageAttested",
  "binaryauthorization.policy.get",
  "binaryauthorization.policy.getIamPolicy",
  "binaryauthorization.policy.setIamPolicy",
  "binaryauthorization.policy.update",
  "clientauthconfig.brands.create",
  "clientauthconfig.brands.delete",
  "clientauthconfig.brands.get",
  "clientauthconfig.brands.list",
  "clientauthconfig.brands.update",
  "clientauthconfig.clients.create",
  "clientauthconfig.clients.createSecret",
  "clientauthconfig.clients.delete",
  "clientauthconfig.clients.get",
  "clientauthconfig.clients.getWithSecret",
  "clientauthconfig.clients.list",
  "clientauthconfig.clients.listWithSecrets",
  "clientauthconfig.clients.undelete",
  "clientauthconfig.clients.update",
  "cloudasset.assets.exportAll",
  "cloudbuild.builds.create",
  "cloudbuild.builds.get",
  "cloudbuild.builds.list",
  "cloudbuild.builds.update",
  "cloudconfig.configs.get",
  "cloudconfig.configs.update",
  "clouddebugger.breakpoints.create",
  "clouddebugger.breakpoints.delete",
  "clouddebugger.breakpoints.get",
  "clouddebugger.breakpoints.list",
  "clouddebugger.breakpoints.listActive",
  "clouddebugger.breakpoints.update",
  "clouddebugger.debuggees.create",
  "clouddebugger.debuggees.list",
  "cloudfunctions.functions.call",
  "cloudfunctions.functions.create",
  "cloudfunctions.functions.delete",
  "cloudfunctions.functions.get",
  "cloudfunctions.functions.list",
  "cloudfunctions.functions.sourceCodeGet",
  "cloudfunctions.functions.sourceCodeSet",
  "cloudfunctions.functions.update",
  "cloudfunctions.locations.list",
  "cloudfunctions.operations.get",
  "cloudfunctions.operations.list",
  "cloudiot.devices.create",
  "cloudiot.devices.delete",
  "cloudiot.devices.get",
  "cloudiot.devices.list",
  "cloudiot.devices.update",
  "cloudiot.devices.updateConfig",
  "cloudiot.registries.create",
  "cloudiot.registries.delete",
  "cloudiot.registries.get",
  "cloudiot.registries.getIamPolicy",
  "cloudiot.registries.list",
  "cloudiot.registries.setIamPolicy",
  "cloudiot.registries.update",
  "cloudjobdiscovery.companies.create",
  "cloudjobdiscovery.companies.delete",
  "cloudjobdiscovery.companies.get",
  "cloudjobdiscovery.companies.list",
  "cloudjobdiscovery.companies.update",
  "cloudjobdiscovery.events.create",
  "cloudjobdiscovery.events.delete",
  "cloudjobdiscovery.events.get",
  "cloudjobdiscovery.events.list",
  "cloudjobdiscovery.events.update",
  "cloudjobdiscovery.jobs.create",
  "cloudjobdiscovery.jobs.delete",
  "cloudjobdiscovery.jobs.deleteByFilter",
  "cloudjobdiscovery.jobs.get",
  "cloudjobdiscovery.jobs.search",
  "cloudjobdiscovery.jobs.update",
  "cloudjobdiscovery.tools.access",
  "cloudkms.cryptoKeyVersions.create",
  "cloudkms.cryptoKeyVersions.destroy",
  "cloudkms.cryptoKeyVersions.get",
  "cloudkms.cryptoKeyVersions.list",
  "cloudkms.cryptoKeyVersions.restore",
  "cloudkms.cryptoKeyVersions.update",
  "cloudkms.cryptoKeyVersions.useToDecrypt",
  "cloudkms.cryptoKeyVersions.useToEncrypt",
  "cloudkms.cryptoKeyVersions.useToSign",
  "cloudkms.cryptoKeyVersions.viewPublicKey",
  "cloudkms.cryptoKeys.create",
  "cloudkms.cryptoKeys.get",
  "cloudkms.cryptoKeys.getIamPolicy",
  "cloudkms.cryptoKeys.list",
  "cloudkms.cryptoKeys.setIamPolicy",
  "cloudkms.cryptoKeys.update",
  "cloudkms.keyRings.create",
  "cloudkms.keyRings.get",
  "cloudkms.keyRings.getIamPolicy",
  "cloudkms.keyRings.list",
  "cloudkms.keyRings.setIamPolicy",
  "cloudnotifications.activities.list",
  "cloudprivatecatalog.targets.get",
  "cloudprivatecatalogproducer.associations.create",
  "cloudprivatecatalogproducer.associations.delete",
  "cloudprivatecatalogproducer.associations.get",
  "cloudprivatecatalogproducer.associations.list",
  "cloudprivatecatalogproducer.catalogs.create",
  "cloudprivatecatalogproducer.catalogs.delete",
  "cloudprivatecatalogproducer.catalogs.get",
  "cloudprivatecatalogproducer.catalogs.getIamPolicy",
  "cloudprivatecatalogproducer.catalogs.list",
  "cloudprivatecatalogproducer.catalogs.setIamPolicy",
  "cloudprivatecatalogproducer.catalogs.undelete",
  "cloudprivatecatalogproducer.catalogs.update",
  "cloudprivatecatalogproducer.targets.associate",
  "cloudprivatecatalogproducer.targets.unassociate",
  "cloudprofiler.profiles.create",
  "cloudprofiler.profiles.list",
  "cloudprofiler.profiles.update",
  "cloudscheduler.jobs.create",
  "cloudscheduler.jobs.delete",
  "cloudscheduler.jobs.enable",
  "cloudscheduler.jobs.fullView",
  "cloudscheduler.jobs.get",
  "cloudscheduler.jobs.list",
  "cloudscheduler.jobs.pause",
  "cloudscheduler.jobs.run",
  "cloudscheduler.jobs.update",
  "cloudsecurityscanner.crawledurls.list",
  "cloudsecurityscanner.results.get",
  "cloudsecurityscanner.results.list",
  "cloudsecurityscanner.scanruns.get",
  "cloudsecurityscanner.scanruns.getSummary",
  "cloudsecurityscanner.scanruns.list",
  "cloudsecurityscanner.scanruns.stop",
  "cloudsecurityscanner.scans.create",
  "cloudsecurityscanner.scans.delete",
  "cloudsecurityscanner.scans.get",
  "cloudsecurityscanner.scans.list",
  "cloudsecurityscanner.scans.run",
  "cloudsecurityscanner.scans.update",
  "cloudsql.backupRuns.create",
  "cloudsql.backupRuns.delete",
  "cloudsql.backupRuns.get",
  "cloudsql.backupRuns.list",
  "cloudsql.databases.create",
  "cloudsql.databases.delete",
  "cloudsql.databases.get",
  "cloudsql.databases.list",
  "cloudsql.databases.update",
  "cloudsql.instances.clone",
  "cloudsql.instances.connect",
  "cloudsql.instances.create",
  "cloudsql.instances.delete",
  "cloudsql.instances.demoteMaster",
  "cloudsql.instances.export",
  "cloudsql.instances.failover",
  "cloudsql.instances.get",
  "cloudsql.instances.import",
  "cloudsql.instances.list",
  "cloudsql.instances.promoteReplica",
  "cloudsql.instances.resetSslConfig",
  "cloudsql.instances.restart",
  "cloudsql.instances.restoreBackup",
  "cloudsql.instances.startReplica",
  "cloudsql.instances.stopReplica",
  "cloudsql.instances.truncateLog",
  "cloudsql.instances.update",
  "cloudsql.sslCerts.create",
  "cloudsql.sslCerts.createEphemeral",
  "cloudsql.sslCerts.delete",
  "cloudsql.sslCerts.get",
  "cloudsql.sslCerts.list",
  "cloudsql.users.create",
  "cloudsql.users.delete",
  "cloudsql.users.list",
  "cloudsql.users.update",
  "cloudsupport.accounts.create",
  "cloudsupport.accounts.delete",
  "cloudsupport.accounts.get",
  "cloudsupport.accounts.getIamPolicy",
  "cloudsupport.accounts.getUserRoles",
  "cloudsupport.accounts.list",
  "cloudsupport.accounts.setIamPolicy",
  "cloudsupport.accounts.update",
  "cloudsupport.accounts.updateUserRoles",
  "cloudsupport.operations.get",
  "cloudtasks.locations.get",
  "cloudtasks.locations.list",
  "cloudtasks.queues.create",
  "cloudtasks.queues.delete",
  "cloudtasks.queues.get",
  "cloudtasks.queues.getIamPolicy",
  "cloudtasks.queues.list",
  "cloudtasks.queues.pause",
  "cloudtasks.queues.purge",
  "cloudtasks.queues.resume",
  "cloudtasks.queues.setIamPolicy",
  "cloudtasks.queues.update",
  "cloudtasks.tasks.create",
  "cloudtasks.tasks.delete",
  "cloudtasks.tasks.fullView",
  "cloudtasks.tasks.get",
  "cloudtasks.tasks.list",
  "cloudtasks.tasks.run",
  "cloudtestservice.environmentcatalog.get",
  "cloudtestservice.matrices.create",
  "cloudtestservice.matrices.delete",
  "cloudtestservice.matrices.get",
  "cloudtestservice.matrices.update",
  "cloudtoolresults.executions.create",
  "cloudtoolresults.executions.get",
  "cloudtoolresults.executions.list",
  "cloudtoolresults.executions.update",
  "cloudtoolresults.histories.create",
  "cloudtoolresults.histories.get",
  "cloudtoolresults.histories.list",
  "cloudtoolresults.settings.create",
  "cloudtoolresults.settings.get",
  "cloudtoolresults.settings.update",
  "cloudtoolresults.steps.create",
  "cloudtoolresults.steps.get",
  "cloudtoolresults.steps.list",
  "cloudtoolresults.steps.update",
  "cloudtrace.insights.get",
  "cloudtrace.insights.list",
  "cloudtrace.stats.get",
  "cloudtrace.tasks.create",
  "cloudtrace.tasks.delete",
  "cloudtrace.tasks.get",
  "cloudtrace.tasks.list",
  "cloudtrace.traces.get",
  "cloudtrace.traces.list",
  "cloudtrace.traces.patch",
  "composer.environments.create",
  "composer.environments.delete",
  "composer.environments.get",
  "composer.environments.list",
  "composer.environments.update",
  "composer.operations.delete",
  "composer.operations.get",
  "composer.operations.list",
  "compute.acceleratorTypes.get",
  "compute.acceleratorTypes.list",
  "compute.addresses.create",
  "compute.addresses.createInternal",
  "compute.addresses.delete",
  "compute.addresses.deleteInternal",
  "compute.addresses.get",
  "compute.addresses.list",
  "compute.addresses.setLabels",
  "compute.addresses.use",
  "compute.addresses.useInternal",
  "compute.autoscalers.create",
  "compute.autoscalers.delete",
  "compute.autoscalers.get",
  "compute.autoscalers.list",
  "compute.autoscalers.update",
  "compute.backendBuckets.create",
  "compute.backendBuckets.delete",
  "compute.backendBuckets.get",
  "compute.backendBuckets.list",
  "compute.backendBuckets.update",
  "compute.backendBuckets.use",
  "compute.backendServices.create",
  "compute.backendServices.delete",
  "compute.backendServices.get",
  "compute.backendServices.list",
  "compute.backendServices.setSecurityPolicy",
  "compute.backendServices.update",
  "compute.backendServices.use",
  "compute.commitments.create",
  "compute.commitments.get",
  "compute.commitments.list",
  "compute.diskTypes.get",
  "compute.diskTypes.list",
  "compute.disks.create",
  "compute.disks.createSnapshot",
  "compute.disks.delete",
  "compute.disks.get",
  "compute.disks.getIamPolicy",
  "compute.disks.list",
  "compute.disks.resize",
  "compute.disks.setIamPolicy",
  "compute.disks.setLabels",
  "compute.disks.update",
  "compute.disks.use",
  "compute.disks.useReadOnly",
  "compute.firewalls.create",
  "compute.firewalls.delete",
  "compute.firewalls.get",
  "compute.firewalls.list",
  "compute.firewalls.update",
  "compute.forwardingRules.create",
  "compute.forwardingRules.delete",
  "compute.forwardingRules.get",
  "compute.forwardingRules.list",
  "compute.forwardingRules.setLabels",
  "compute.forwardingRules.setTarget",
  "compute.globalAddresses.create",
  "compute.globalAddresses.createInternal",
  "compute.globalAddresses.delete",
  "compute.globalAddresses.deleteInternal",
  "compute.globalAddresses.get",
  "compute.globalAddresses.list",
  "compute.globalAddresses.setLabels",
  "compute.globalAddresses.use",
  "compute.globalForwardingRules.create",
  "compute.globalForwardingRules.delete",
  "compute.globalForwardingRules.get",
  "compute.globalForwardingRules.list",
  "compute.globalForwardingRules.setLabels",
  "compute.globalForwardingRules.setTarget",
  "compute.globalOperations.delete",
  "compute.globalOperations.get",
  "compute.globalOperations.getIamPolicy",
  "compute.globalOperations.list",
  "compute.globalOperations.setIamPolicy",
  "compute.healthChecks.create",
  "compute.healthChecks.delete",
  "compute.healthChecks.get",
  "compute.healthChecks.list",
  "compute.healthChecks.update",
  "compute.healthChecks.use",
  "compute.healthChecks.useReadOnly",
  "compute.httpHealthChecks.create",
  "compute.httpHealthChecks.delete",
  "compute.httpHealthChecks.get",
  "compute.httpHealthChecks.list",
  "compute.httpHealthChecks.update",
  "compute.httpHealthChecks.use",
  "compute.httpHealthChecks.useReadOnly",
  "compute.httpsHealthChecks.create",
  "compute.httpsHealthChecks.delete",
  "compute.httpsHealthChecks.get",
  "compute.httpsHealthChecks.list",
  "compute.httpsHealthChecks.update",
  "compute.httpsHealthChecks.use",
  "compute.httpsHealthChecks.useReadOnly",
  "compute.images.create",
  "compute.images.delete",
  "compute.images.deprecate",
  "compute.images.get",
  "compute.images.getFromFamily",
  "compute.images.getIamPolicy",
  "compute.images.list",
  "compute.images.setIamPolicy",
  "compute.images.setLabels",
  "compute.images.update",
  "compute.images.useReadOnly",
  "compute.instanceGroupManagers.create",
  "compute.instanceGroupManagers.delete",
  "compute.instanceGroupManagers.get",
  "compute.instanceGroupManagers.list",
  "compute.instanceGroupManagers.update",
  "compute.instanceGroupManagers.use",
  "compute.instanceGroups.create",
  "compute.instanceGroups.delete",
  "compute.instanceGroups.get",
  "compute.instanceGroups.list",
  "compute.instanceGroups.update",
  "compute.instanceGroups.use",
  "compute.instanceTemplates.create",
  "compute.instanceTemplates.delete",
  "compute.instanceTemplates.get",
  "compute.instanceTemplates.getIamPolicy",
  "compute.instanceTemplates.list",
  "compute.instanceTemplates.setIamPolicy",
  "compute.instanceTemplates.useReadOnly",
  "compute.instances.addAccessConfig",
  "compute.instances.addMaintenancePolicies",
  "compute.instances.attachDisk",
  "compute.instances.create",
  "compute.instances.delete",
  "compute.instances.deleteAccessConfig",
  "compute.instances.detachDisk",
  "compute.instances.get",
  "compute.instances.getGuestAttributes",
  "compute.instances.getIamPolicy",
  "compute.instances.getSerialPortOutput",
  "compute.instances.list",
  "compute.instances.listReferrers",
  "compute.instances.osAdminLogin",
  "compute.instances.osLogin",
  "compute.instances.removeMaintenancePolicies",
  "compute.instances.reset",
  "compute.instances.resume",
  "compute.instances.setDeletionProtection",
  "compute.instances.setDiskAutoDelete",
  "compute.instances.setIamPolicy",
  "compute.instances.setLabels",
  "compute.instances.setMachineResources",
  "compute.instances.setMachineType",
  "compute.instances.setMetadata",
  "compute.instances.setMinCpuPlatform",
  "compute.instances.setScheduling",
  "compute.instances.setServiceAccount",
  "compute.instances.setShieldedVmIntegrityPolicy",
  "compute.instances.setTags",
  "compute.instances.start",
  "compute.instances.startWithEncryptionKey",
  "compute.instances.stop",
  "compute.instances.suspend",
  "compute.instances.update",
  "compute.instances.updateAccessConfig",
  "compute.instances.updateNetworkInterface",
  "compute.instances.updateShieldedVmConfig",
  "compute.instances.use",
  "compute.interconnectAttachments.create",
  "compute.interconnectAttachments.delete",
  "compute.interconnectAttachments.get",
  "compute.interconnectAttachments.list",
  "compute.interconnectAttachments.setLabels",
  "compute.interconnectAttachments.update",
  "compute.interconnectAttachments.use",
  "compute.interconnectLocations.get",
  "compute.interconnectLocations.list",
  "compute.interconnects.create",
  "compute.interconnects.delete",
  "compute.interconnects.get",
  "compute.interconnects.list",
  "compute.interconnects.setLabels",
  "compute.interconnects.update",
  "compute.interconnects.use",
  "compute.licenseCodes.get",
  "compute.licenseCodes.getIamPolicy",
  "compute.licenseCodes.list",
  "compute.licenseCodes.setIamPolicy",
  "compute.licenseCodes.update",
  "compute.licenseCodes.use",
  "compute.licenses.create",
  "compute.licenses.delete",
  "compute.licenses.get",
  "compute.licenses.getIamPolicy",
  "compute.licenses.list",
  "compute.licenses.setIamPolicy",
  "compute.machineTypes.get",
  "compute.machineTypes.list",
  "compute.maintenancePolicies.create",
  "compute.maintenancePolicies.delete",
  "compute.maintenancePolicies.get",
  "compute.maintenancePolicies.getIamPolicy",
  "compute.maintenancePolicies.list",
  "compute.maintenancePolicies.setIamPolicy",
  "compute.maintenancePolicies.use",
  "compute.networks.addPeering",
  "compute.networks.create",
  "compute.networks.delete",
  "compute.networks.get",
  "compute.networks.list",
  "compute.networks.removePeering",
  "compute.networks.switchToCustomMode",
  "compute.networks.update",
  "compute.networks.updatePeering",
  "compute.networks.updatePolicy",
  "compute.networks.use",
  "compute.networks.useExternalIp",
  "compute.nodeGroups.addNodes",
  "compute.nodeGroups.create",
  "compute.nodeGroups.delete",
  "compute.nodeGroups.deleteNodes",
  "compute.nodeGroups.get",
  "compute.nodeGroups.getIamPolicy",
  "compute.nodeGroups.list",
  "compute.nodeGroups.setIamPolicy",
  "compute.nodeGroups.setNodeTemplate",
  "compute.nodeTemplates.create",
  "compute.nodeTemplates.delete",
  "compute.nodeTemplates.get",
  "compute.nodeTemplates.getIamPolicy",
  "compute.nodeTemplates.list",
  "compute.nodeTemplates.setIamPolicy",
  "compute.nodeTypes.get",
  "compute.nodeTypes.list",
  "compute.oslogin.updateExternalUser",
  "compute.projects.get",
  "compute.projects.setCommonInstanceMetadata",
  "compute.projects.setDefaultNetworkTier",
  "compute.projects.setDefaultServiceAccount",
  "compute.projects.setUsageExportBucket",
  "compute.regionBackendServices.create",
  "compute.regionBackendServices.delete",
  "compute.regionBackendServices.get",
  "compute.regionBackendServices.list",
  "compute.regionBackendServices.setSecurityPolicy",
  "compute.regionBackendServices.update",
  "compute.regionBackendServices.use",
  "compute.regionOperations.delete",
  "compute.regionOperations.get",
  "compute.regionOperations.getIamPolicy",
  "compute.regionOperations.list",
  "compute.regionOperations.setIamPolicy",
  "compute.regions.get",
  "compute.regions.list",
  "compute.routers.create",
  "compute.routers.delete",
  "compute.routers.get",
  "compute.routers.list",
  "compute.routers.update",
  "compute.routers.use",
  "compute.routes.create",
  "compute.routes.delete",
  "compute.routes.get",
  "compute.routes.list",
  "compute.securityPolicies.create",
  "compute.securityPolicies.delete",
  "compute.securityPolicies.get",
  "compute.securityPolicies.getIamPolicy",
  "compute.securityPolicies.list",
  "compute.securityPolicies.setIamPolicy",
  "compute.securityPolicies.update",
  "compute.securityPolicies.use",
  "compute.snapshots.create",
  "compute.snapshots.delete",
  "compute.snapshots.get",
  "compute.snapshots.getIamPolicy",
  "compute.snapshots.list",
  "compute.snapshots.setIamPolicy",
  "compute.snapshots.setLabels",
  "compute.snapshots.useReadOnly",
  "compute.sslCertificates.create",
  "compute.sslCertificates.delete",
  "compute.sslCertificates.get",
  "compute.sslCertificates.list",
  "compute.sslPolicies.create",
  "compute.sslPolicies.delete",
  "compute.sslPolicies.get",
  "compute.sslPolicies.list",
  "compute.sslPolicies.listAvailableFeatures",
  "compute.sslPolicies.update",
  "compute.sslPolicies.use",
  "compute.subnetworks.create",
  "compute.subnetworks.delete",
  "compute.subnetworks.expandIpCidrRange",
  "compute.subnetworks.get",
  "compute.subnetworks.getIamPolicy",
  "compute.subnetworks.list",
  "compute.subnetworks.setIamPolicy",
  "compute.subnetworks.setPrivateIpGoogleAccess",
  "compute.subnetworks.update",
  "compute.subnetworks.use",
  "compute.subnetworks.useExternalIp",
  "compute.targetHttpProxies.create",
  "compute.targetHttpProxies.delete",
  "compute.targetHttpProxies.get",
  "compute.targetHttpProxies.list",
  "compute.targetHttpProxies.setUrlMap",
  "compute.targetHttpProxies.use",
  "compute.targetHttpsProxies.create",
  "compute.targetHttpsProxies.delete",
  "compute.targetHttpsProxies.get",
  "compute.targetHttpsProxies.list",
  "compute.targetHttpsProxies.setSslCertificates",
  "compute.targetHttpsProxies.setSslPolicy",
  "compute.targetHttpsProxies.setUrlMap",
  "compute.targetHttpsProxies.use",
  "compute.targetInstances.create",
  "compute.targetInstances.delete",
  "compute.targetInstances.get",
  "compute.targetInstances.list",
  "compute.targetInstances.use",
  "compute.targetPools.addHealthCheck",
  "compute.targetPools.addInstance",
  "compute.targetPools.create",
  "compute.targetPools.delete",
  "compute.targetPools.get",
  "compute.targetPools.list",
  "compute.targetPools.removeHealthCheck",
  "compute.targetPools.removeInstance",
  "compute.targetPools.update",
  "compute.targetPools.use",
  "compute.targetSslProxies.create",
  "compute.targetSslProxies.delete",
  "compute.targetSslProxies.get",
  "compute.targetSslProxies.list",
  "compute.targetSslProxies.setBackendService",
  "compute.targetSslProxies.setProxyHeader",
  "compute.targetSslProxies.setSslCertificates",
  "compute.targetSslProxies.use",
  "compute.targetTcpProxies.create",
  "compute.targetTcpProxies.delete",
  "compute.targetTcpProxies.get",
  "compute.targetTcpProxies.list",
  "compute.targetTcpProxies.update",
  "compute.targetTcpProxies.use",
  "compute.targetVpnGateways.create",
  "compute.targetVpnGateways.delete",
  "compute.targetVpnGateways.get",
  "compute.targetVpnGateways.list",
  "compute.targetVpnGateways.setLabels",
  "compute.targetVpnGateways.use",
  "compute.urlMaps.create",
  "compute.urlMaps.delete",
  "compute.urlMaps.get",
  "compute.urlMaps.invalidateCache",
  "compute.urlMaps.list",
  "compute.urlMaps.update",
  "compute.urlMaps.use",
  "compute.urlMaps.validate",
  "compute.vpnTunnels.create",
  "compute.vpnTunnels.delete",
  "compute.vpnTunnels.get",
  "compute.vpnTunnels.list",
  "compute.vpnTunnels.setLabels",
  "compute.zoneOperations.delete",
  "compute.zoneOperations.get",
  "compute.zoneOperations.getIamPolicy",
  "compute.zoneOperations.list",
  "compute.zoneOperations.setIamPolicy",
  "compute.zones.get",
  "compute.zones.list",
  "container.apiServices.create",
  "container.apiServices.delete",
  "container.apiServices.get",
  "container.apiServices.list",
  "container.apiServices.update",
  "container.apiServices.updateStatus",
  "container.backendConfigs.create",
  "container.backendConfigs.delete",
  "container.backendConfigs.get",
  "container.backendConfigs.list",
  "container.backendConfigs.update",
  "container.bindings.create",
  "container.bindings.delete",
  "container.bindings.get",
  "container.bindings.list",
  "container.bindings.update",
  "container.certificateSigningRequests.approve",
  "container.certificateSigningRequests.create",
  "container.certificateSigningRequests.delete",
  "container.certificateSigningRequests.get",
  "container.certificateSigningRequests.list",
  "container.certificateSigningRequests.update",
  "container.certificateSigningRequests.updateStatus",
  "container.clusterRoleBindings.create",
  "container.clusterRoleBindings.delete",
  "container.clusterRoleBindings.get",
  "container.clusterRoleBindings.list",
  "container.clusterRoleBindings.update",
  "container.clusterRoles.bind",
  "container.clusterRoles.create",
  "container.clusterRoles.delete",
  "container.clusterRoles.get",
  "container.clusterRoles.list",
  "container.clusterRoles.update",
  "container.clusters.create",
  "container.clusters.delete",
  "container.clusters.get",
  "container.clusters.getCredentials",
  "container.clusters.list",
  "container.clusters.update",
  "container.componentStatuses.get",
  "container.componentStatuses.list",
  "container.configMaps.create",
  "container.configMaps.delete",
  "container.configMaps.get",
  "container.configMaps.list",
  "container.configMaps.update",
  "container.controllerRevisions.create",
  "container.controllerRevisions.delete",
  "container.controllerRevisions.get",
  "container.controllerRevisions.list",
  "container.controllerRevisions.update",
  "container.cronJobs.create",
  "container.cronJobs.delete",
  "container.cronJobs.get",
  "container.cronJobs.getStatus",
  "container.cronJobs.list",
  "container.cronJobs.update",
  "container.cronJobs.updateStatus",
  "container.customResourceDefinitions.create",
  "container.customResourceDefinitions.delete",
  "container.customResourceDefinitions.get",
  "container.customResourceDefinitions.list",
  "container.customResourceDefinitions.update",
  "container.customResourceDefinitions.updateStatus",
  "container.daemonSets.create",
  "container.daemonSets.delete",
  "container.daemonSets.get",
  "container.daemonSets.getStatus",
  "container.daemonSets.list",
  "container.daemonSets.update",
  "container.daemonSets.updateStatus",
  "container.deployments.create",
  "container.deployments.delete",
  "container.deployments.get",
  "container.deployments.getScale",
  "container.deployments.getStatus",
  "container.deployments.list",
  "container.deployments.rollback",
  "container.deployments.update",
  "container.deployments.updateScale",
  "container.deployments.updateStatus",
  "container.endpoints.create",
  "container.endpoints.delete",
  "container.endpoints.get",
  "container.endpoints.list",
  "container.endpoints.update",
  "container.events.create",
  "container.events.delete",
  "container.events.get",
  "container.events.list",
  "container.events.update",
  "container.horizontalPodAutoscalers.create",
  "container.horizontalPodAutoscalers.delete",
  "container.horizontalPodAutoscalers.get",
  "container.horizontalPodAutoscalers.getStatus",
  "container.horizontalPodAutoscalers.list",
  "container.horizontalPodAutoscalers.update",
  "container.horizontalPodAutoscalers.updateStatus",
  "container.ingresses.create",
  "container.ingresses.delete",
  "container.ingresses.get",
  "container.ingresses.getStatus",
  "container.ingresses.list",
  "container.ingresses.update",
  "container.ingresses.updateStatus",
  "container.initializerConfigurations.create",
  "container.initializerConfigurations.delete",
  "container.initializerConfigurations.get",
  "container.initializerConfigurations.list",
  "container.initializerConfigurations.update",
  "container.jobs.create",
  "container.jobs.delete",
  "container.jobs.get",
  "container.jobs.getStatus",
  "container.jobs.list",
  "container.jobs.update",
  "container.jobs.updateStatus",
  "container.limitRanges.create",
  "container.limitRanges.delete",
  "container.limitRanges.get",
  "container.limitRanges.list",
  "container.limitRanges.update",
  "container.localSubjectAccessReviews.create",
  "container.localSubjectAccessReviews.list",
  "container.namespaces.create",
  "container.namespaces.delete",
  "container.namespaces.get",
  "container.namespaces.getStatus",
  "container.namespaces.list",
  "container.namespaces.update",
  "container.namespaces.updateStatus",
  "container.networkPolicies.create",
  "container.networkPolicies.delete",
  "container.networkPolicies.get",
  "container.networkPolicies.list",
  "container.networkPolicies.update",
  "container.nodes.create",
  "container.nodes.delete",
  "container.nodes.get",
  "container.nodes.getStatus",
  "container.nodes.list",
  "container.nodes.proxy",
  "container.nodes.update",
  "container.nodes.updateStatus",
  "container.operations.get",
  "container.operations.list",
  "container.persistentVolumeClaims.create",
  "container.persistentVolumeClaims.delete",
  "container.persistentVolumeClaims.get",
  "container.persistentVolumeClaims.getStatus",
  "container.persistentVolumeClaims.list",
  "container.persistentVolumeClaims.update",
  "container.persistentVolumeClaims.updateStatus",
  "container.persistentVolumes.create",
  "container.persistentVolumes.delete",
  "container.persistentVolumes.get",
  "container.persistentVolumes.getStatus",
  "container.persistentVolumes.list",
  "container.persistentVolumes.update",
  "container.persistentVolumes.updateStatus",
  "container.petSets.create",
  "container.petSets.delete",
  "container.petSets.get",
  "container.petSets.list",
  "container.petSets.update",
  "container.petSets.updateStatus",
  "container.podDisruptionBudgets.create",
  "container.podDisruptionBudgets.delete",
  "container.podDisruptionBudgets.get",
  "container.podDisruptionBudgets.getStatus",
  "container.podDisruptionBudgets.list",
  "container.podDisruptionBudgets.update",
  "container.podDisruptionBudgets.updateStatus",
  "container.podPresets.create",
  "container.podPresets.delete",
  "container.podPresets.get",
  "container.podPresets.list",
  "container.podPresets.update",
  "container.podSecurityPolicies.create",
  "container.podSecurityPolicies.delete",
  "container.podSecurityPolicies.get",
  "container.podSecurityPolicies.list",
  "container.podSecurityPolicies.update",
  "container.podSecurityPolicies.use",
  "container.podTemplates.create",
  "container.podTemplates.delete",
  "container.podTemplates.get",
  "container.podTemplates.list",
  "container.podTemplates.update",
  "container.pods.attach",
  "container.pods.create",
  "container.pods.delete",
  "container.pods.evict",
  "container.pods.exec",
  "container.pods.get",
  "container.pods.getLogs",
  "container.pods.getStatus",
  "container.pods.initialize",
  "container.pods.list",
  "container.pods.portForward",
  "container.pods.proxy",
  "container.pods.update",
  "container.pods.updateStatus",
  "container.replicaSets.create",
  "container.replicaSets.delete",
  "container.replicaSets.get",
  "container.replicaSets.getScale",
  "container.replicaSets.getStatus",
  "container.replicaSets.list",
  "container.replicaSets.update",
  "container.replicaSets.updateScale",
  "container.replicaSets.updateStatus",
  "container.replicationControllers.create",
  "container.replicationControllers.delete",
  "container.replicationControllers.get",
  "container.replicationControllers.getScale",
  "container.replicationControllers.getStatus",
  "container.replicationControllers.list",
  "container.replicationControllers.update",
  "container.replicationControllers.updateScale",
  "container.replicationControllers.updateStatus",
  "container.resourceQuotas.create",
  "container.resourceQuotas.delete",
  "container.resourceQuotas.get",
  "container.resourceQuotas.getStatus",
  "container.resourceQuotas.list",
  "container.resourceQuotas.update",
  "container.resourceQuotas.updateStatus",
  "container.roleBindings.create",
  "container.roleBindings.delete",
  "container.roleBindings.get",
  "container.roleBindings.list",
  "container.roleBindings.update",
  "container.roles.bind",
  "container.roles.create",
  "container.roles.delete",
  "container.roles.get",
  "container.roles.list",
  "container.roles.update",
  "container.scheduledJobs.create",
  "container.scheduledJobs.delete",
  "container.scheduledJobs.get",
  "container.scheduledJobs.list",
  "container.scheduledJobs.update",
  "container.scheduledJobs.updateStatus",
  "container.secrets.create",
  "container.secrets.delete",
  "container.secrets.get",
  "container.secrets.list",
  "container.secrets.update",
  "container.selfSubjectAccessReviews.create",
  "container.selfSubjectAccessReviews.list",
  "container.serviceAccounts.create",
  "container.serviceAccounts.delete",
  "container.serviceAccounts.get",
  "container.serviceAccounts.list",
  "container.serviceAccounts.update",
  "container.services.create",
  "container.services.delete",
  "container.services.get",
  "container.services.getStatus",
  "container.services.list",
  "container.services.proxy",
  "container.services.update",
  "container.services.updateStatus",
  "container.statefulSets.create",
  "container.statefulSets.delete",
  "container.statefulSets.get",
  "container.statefulSets.getScale",
  "container.statefulSets.getStatus",
  "container.statefulSets.list",
  "container.statefulSets.update",
  "container.statefulSets.updateScale",
  "container.statefulSets.updateStatus",
  "container.storageClasses.create",
  "container.storageClasses.delete",
  "container.storageClasses.get",
  "container.storageClasses.list",
  "container.storageClasses.update",
  "container.subjectAccessReviews.create",
  "container.subjectAccessReviews.list",
  "container.thirdPartyObjects.create",
  "container.thirdPartyObjects.delete",
  "container.thirdPartyObjects.get",
  "container.thirdPartyObjects.list",
  "container.thirdPartyObjects.update",
  "container.thirdPartyResources.create",
  "container.thirdPartyResources.delete",
  "container.thirdPartyResources.get",
  "container.thirdPartyResources.list",
  "container.thirdPartyResources.update",
  "container.tokenReviews.create",
  "dataflow.jobs.cancel",
  "dataflow.jobs.create",
  "dataflow.jobs.get",
  "dataflow.jobs.list",
  "dataflow.jobs.updateContents",
  "dataflow.messages.list",
  "dataflow.metrics.get",
  "dataprep.projects.use",
  "dataproc.agents.create",
  "dataproc.agents.delete",
  "dataproc.agents.get",
  "dataproc.agents.list",
  "dataproc.agents.update",
  "dataproc.clusters.create",
  "dataproc.clusters.delete",
  "dataproc.clusters.get",
  "dataproc.clusters.getIamPolicy",
  "dataproc.clusters.list",
  "dataproc.clusters.setIamPolicy",
  "dataproc.clusters.update",
  "dataproc.clusters.use",
  "dataproc.jobs.cancel",
  "dataproc.jobs.create",
  "dataproc.jobs.delete",
  "dataproc.jobs.get",
  "dataproc.jobs.getIamPolicy",
  "dataproc.jobs.list",
  "dataproc.jobs.setIamPolicy",
  "dataproc.jobs.update",
  "dataproc.operations.cancel",
  "dataproc.operations.delete",
  "dataproc.operations.get",
  "dataproc.operations.getIamPolicy",
  "dataproc.operations.list",
  "dataproc.operations.setIamPolicy",
  "dataproc.tasks.lease",
  "dataproc.tasks.listInvalidatedLeases",
  "dataproc.tasks.reportStatus",
  "dataproc.workflowTemplates.create",
  "dataproc.workflowTemplates.delete",
  "dataproc.workflowTemplates.get",
  "dataproc.workflowTemplates.getIamPolicy",
  "dataproc.workflowTemplates.instantiate",
  "dataproc.workflowTemplates.instantiateInline",
  "dataproc.workflowTemplates.list",
  "dataproc.workflowTemplates.setIamPolicy",
  "dataproc.workflowTemplates.update",
  "datastore.databases.create",
  "datastore.databases.delete",
  "datastore.databases.export",
  "datastore.databases.get",
  "datastore.databases.getIamPolicy",
  "datastore.databases.import",
  "datastore.databases.list",
  "datastore.databases.setIamPolicy",
  "datastore.databases.update",
  "datastore.entities.allocateIds",
  "datastore.entities.create",
  "datastore.entities.delete",
  "datastore.entities.get",
  "datastore.entities.list",
  "datastore.entities.update",
  "datastore.indexes.create",
  "datastore.indexes.delete",
  "datastore.indexes.get",
  "datastore.indexes.list",
  "datastore.indexes.update",
  "datastore.locations.get",
  "datastore.locations.list",
  "datastore.namespaces.get",
  "datastore.namespaces.getIamPolicy",
  "datastore.namespaces.list",
  "datastore.namespaces.setIamPolicy",
  "datastore.operations.cancel",
  "datastore.operations.delete",
  "datastore.operations.get",
  "datastore.operations.list",
  "datastore.statistics.get",
  "datastore.statistics.list",
  "deploymentmanager.compositeTypes.create",
  "deploymentmanager.compositeTypes.delete",
  "deploymentmanager.compositeTypes.get",
  "deploymentmanager.compositeTypes.list",
  "deploymentmanager.compositeTypes.update",
  "deploymentmanager.deployments.cancelPreview",
  "deploymentmanager.deployments.create",
  "deploymentmanager.deployments.delete",
  "deploymentmanager.deployments.get",
  "deploymentmanager.deployments.getIamPolicy",
  "deploymentmanager.deployments.list",
  "deploymentmanager.deployments.setIamPolicy",
  "deploymentmanager.deployments.stop",
  "deploymentmanager.deployments.update",
  "deploymentmanager.manifests.get",
  "deploymentmanager.manifests.list",
  "deploymentmanager.operations.get",
  "deploymentmanager.operations.list",
  "deploymentmanager.resources.get",
  "deploymentmanager.resources.list",
  "deploymentmanager.typeProviders.create",
  "deploymentmanager.typeProviders.delete",
  "deploymentmanager.typeProviders.get",
  "deploymentmanager.typeProviders.getType",
  "deploymentmanager.typeProviders.list",
  "deploymentmanager.typeProviders.listTypes",
  "deploymentmanager.typeProviders.update",
  "deploymentmanager.types.create",
  "deploymentmanager.types.delete",
  "deploymentmanager.types.get",
  "deploymentmanager.types.list",
  "deploymentmanager.types.update",
  "dialogflow.agents.export",
  "dialogflow.agents.get",
  "dialogflow.agents.import",
  "dialogflow.agents.restore",
  "dialogflow.agents.search",
  "dialogflow.agents.train",
  "dialogflow.contexts.create",
  "dialogflow.contexts.delete",
  "dialogflow.contexts.get",
  "dialogflow.contexts.list",
  "dialogflow.contexts.update",
  "dialogflow.entityTypes.create",
  "dialogflow.entityTypes.createEntity",
  "dialogflow.entityTypes.delete",
  "dialogflow.entityTypes.deleteEntity",
  "dialogflow.entityTypes.get",
  "dialogflow.entityTypes.list",
  "dialogflow.entityTypes.update",
  "dialogflow.entityTypes.updateEntity",
  "dialogflow.intents.create",
  "dialogflow.intents.delete",
  "dialogflow.intents.get",
  "dialogflow.intents.list",
  "dialogflow.intents.update",
  "dialogflow.operations.get",
  "dialogflow.sessionEntityTypes.create",
  "dialogflow.sessionEntityTypes.delete",
  "dialogflow.sessionEntityTypes.get",
  "dialogflow.sessionEntityTypes.list",
  "dialogflow.sessionEntityTypes.update",
  "dialogflow.sessions.detectIntent",
  "dialogflow.sessions.streamingDetectIntent",
  "dlp.analyzeRiskTemplates.create",
  "dlp.analyzeRiskTemplates.delete",
  "dlp.analyzeRiskTemplates.get",
  "dlp.analyzeRiskTemplates.list",
  "dlp.analyzeRiskTemplates.update",
  "dlp.deidentifyTemplates.create",
  "dlp.deidentifyTemplates.delete",
  "dlp.deidentifyTemplates.get",
  "dlp.deidentifyTemplates.list",
  "dlp.deidentifyTemplates.update",
  "dlp.inspectTemplates.create",
  "dlp.inspectTemplates.delete",
  "dlp.inspectTemplates.get",
  "dlp.inspectTemplates.list",
  "dlp.inspectTemplates.update",
  "dlp.jobTriggers.create",
  "dlp.jobTriggers.delete",
  "dlp.jobTriggers.get",
  "dlp.jobTriggers.list",
  "dlp.jobTriggers.update",
  "dlp.jobs.cancel",
  "dlp.jobs.create",
  "dlp.jobs.delete",
  "dlp.jobs.get",
  "dlp.jobs.list",
  "dlp.kms.encrypt",
  "dlp.storedInfoTypes.create",
  "dlp.storedInfoTypes.delete",
  "dlp.storedInfoTypes.get",
  "dlp.storedInfoTypes.list",
  "dlp.storedInfoTypes.update",
  "dns.changes.create",
  "dns.changes.get",
  "dns.changes.list",
  "dns.dnsKeys.get",
  "dns.dnsKeys.list",
  "dns.managedZoneOperations.get",
  "dns.managedZoneOperations.list",
  "dns.managedZones.create",
  "dns.managedZones.delete",
  "dns.managedZones.get",
  "dns.managedZones.list",
  "dns.managedZones.update",
  "dns.projects.get",
  "dns.resourceRecordSets.create",
  "dns.resourceRecordSets.delete",
  "dns.resourceRecordSets.list",
  "dns.resourceRecordSets.update",
  "endpoints.portals.attachCustomDomain",
  "endpoints.portals.detachCustomDomain",
  "endpoints.portals.listCustomDomains",
  "endpoints.portals.update",
  "errorreporting.applications.list",
  "errorreporting.errorEvents.create",
  "errorreporting.errorEvents.delete",
  "errorreporting.errorEvents.list",
  "errorreporting.groupMetadata.get",
  "errorreporting.groupMetadata.update",
  "errorreporting.groups.list",
  "file.instances.create",
  "file.instances.delete",
  "file.instances.get",
  "file.instances.list",
  "file.instances.update",
  "file.locations.get",
  "file.locations.list",
  "file.operations.cancel",
  "file.operations.delete",
  "file.operations.get",
  "file.operations.list",
  "firebase.billingPlans.get",
  "firebase.billingPlans.update",
  "firebase.clients.create",
  "firebase.clients.delete",
  "firebase.clients.get",
  "firebase.links.create",
  "firebase.links.delete",
  "firebase.links.list",
  "firebase.links.update",
  "firebase.projects.delete",
  "firebase.projects.get",
  "firebase.projects.update",
  "firebaseabt.experimentresults.get",
  "firebaseabt.experiments.create",
  "firebaseabt.experiments.delete",
  "firebaseabt.experiments.get",
  "firebaseabt.experiments.list",
  "firebaseabt.experiments.update",
  "firebaseabt.projectmetadata.get",
  "firebaseanalytics.resources.googleAnalyticsEdit",
  "firebaseanalytics.resources.googleAnalyticsReadAndAnalyze",
  "firebaseauth.configs.create",
  "firebaseauth.configs.get",
  "firebaseauth.configs.update",
  "firebaseauth.users.create",
  "firebaseauth.users.createSession",
  "firebaseauth.users.delete",
  "firebaseauth.users.get",
  "firebaseauth.users.sendEmail",
  "firebaseauth.users.update",
  "firebasecrash.issues.update",
  "firebasecrash.reports.get",
  "firebasedatabase.instances.create",
  "firebasedatabase.instances.get",
  "firebasedatabase.instances.list",
  "firebasedatabase.instances.update",
  "firebasedynamiclinks.destinations.list",
  "firebasedynamiclinks.destinations.update",
  "firebasedynamiclinks.domains.create",
  "firebasedynamiclinks.domains.delete",
  "firebasedynamiclinks.domains.get",
  "firebasedynamiclinks.domains.list",
  "firebasedynamiclinks.domains.update",
  "firebasedynamiclinks.links.create",
  "firebasedynamiclinks.links.get",
  "firebasedynamiclinks.links.list",
  "firebasedynamiclinks.links.update",
  "firebasedynamiclinks.stats.get",
  "firebaseextensions.configs.create",
  "firebaseextensions.configs.delete",
  "firebaseextensions.configs.list",
  "firebaseextensions.configs.update",
  "firebasehosting.sites.create",
  "firebasehosting.sites.delete",
  "firebasehosting.sites.get",
  "firebasehosting.sites.list",
  "firebasehosting.sites.update",
  "firebaseinappmessaging.campaigns.create",
  "firebaseinappmessaging.campaigns.delete",
  "firebaseinappmessaging.campaigns.get",
  "firebaseinappmessaging.campaigns.list",
  "firebaseinappmessaging.campaigns.update",
  "firebaseml.compressionjobs.create",
  "firebaseml.compressionjobs.delete",
  "firebaseml.compressionjobs.get",
  "firebaseml.compressionjobs.list",
  "firebaseml.compressionjobs.start",
  "firebaseml.compressionjobs.update",
  "firebaseml.models.create",
  "firebaseml.models.delete",
  "firebaseml.models.get",
  "firebaseml.models.list",
  "firebaseml.modelversions.create",
  "firebaseml.modelversions.get",
  "firebaseml.modelversions.list",
  "firebaseml.modelversions.update",
  "firebasenotifications.messages.create",
  "firebasenotifications.messages.delete",
  "firebasenotifications.messages.get",
  "firebasenotifications.messages.list",
  "firebasenotifications.messages.update",
  "firebaseperformance.config.create",
  "firebaseperformance.config.delete",
  "firebaseperformance.config.update",
  "firebaseperformance.data.get",
  "firebasepredictions.predictions.create",
  "firebasepredictions.predictions.delete",
  "firebasepredictions.predictions.list",
  "firebasepredictions.predictions.update",
  "firebaserules.releases.create",
  "firebaserules.releases.delete",
  "firebaserules.releases.get",
  "firebaserules.releases.getExecutable",
  "firebaserules.releases.list",
  "firebaserules.releases.update",
  "firebaserules.rulesets.create",
  "firebaserules.rulesets.delete",
  "firebaserules.rulesets.get",
  "firebaserules.rulesets.list",
  "firebaserules.rulesets.test",
  "genomics.datasets.create",
  "genomics.datasets.delete",
  "genomics.datasets.get",
  "genomics.datasets.getIamPolicy",
  "genomics.datasets.list",
  "genomics.datasets.setIamPolicy",
  "genomics.datasets.update",
  "genomics.operations.cancel",
  "genomics.operations.create",
  "genomics.operations.get",
  "genomics.operations.list",
  "iam.roles.create",
  "iam.roles.delete",
  "iam.roles.get",
  "iam.roles.list",
  "iam.roles.undelete",
  "iam.roles.update",
  "iam.serviceAccountKeys.create",
  "iam.serviceAccountKeys.delete",
  "iam.serviceAccountKeys.get",
  "iam.serviceAccountKeys.list",
  "iam.serviceAccounts.actAs",
  "iam.serviceAccounts.create",
  "iam.serviceAccounts.delete",
  "iam.serviceAccounts.get",
  "iam.serviceAccounts.getIamPolicy",
  "iam.serviceAccounts.list",
  "iam.serviceAccounts.setIamPolicy",
  "iam.serviceAccounts.update",
  "iap.web.getIamPolicy",
  "iap.web.setIamPolicy",
  "iap.webServiceVersions.getIamPolicy",
  "iap.webServiceVersions.setIamPolicy",
  "iap.webServices.getIamPolicy",
  "iap.webServices.setIamPolicy",
  "iap.webTypes.getIamPolicy",
  "iap.webTypes.setIamPolicy",
  "logging.exclusions.create",
  "logging.exclusions.delete",
  "logging.exclusions.get",
  "logging.exclusions.list",
  "logging.exclusions.update",
  "logging.logEntries.create",
  "logging.logEntries.list",
  "logging.logMetrics.create",
  "logging.logMetrics.delete",
  "logging.logMetrics.get",
  "logging.logMetrics.list",
  "logging.logMetrics.update",
  "logging.logServiceIndexes.list",
  "logging.logServices.list",
  "logging.logs.delete",
  "logging.logs.list",
  "logging.privateLogEntries.list",
  "logging.sinks.create",
  "logging.sinks.delete",
  "logging.sinks.get",
  "logging.sinks.list",
  "logging.sinks.update",
  "logging.usage.get",
  "ml.jobs.cancel",
  "ml.jobs.create",
  "ml.jobs.get",
  "ml.jobs.getIamPolicy",
  "ml.jobs.list",
  "ml.jobs.setIamPolicy",
  "ml.jobs.update",
  "ml.locations.get",
  "ml.locations.list",
  "ml.models.create",
  "ml.models.delete",
  "ml.models.get",
  "ml.models.getIamPolicy",
  "ml.models.list",
  "ml.models.predict",
  "ml.models.setIamPolicy",
  "ml.models.update",
  "ml.operations.cancel",
  "ml.operations.get",
  "ml.operations.list",
  "ml.projects.getConfig",
  "ml.versions.create",
  "ml.versions.delete",
  "ml.versions.get",
  "ml.versions.list",
  "ml.versions.predict",
  "ml.versions.update",
  "monitoring.alertPolicies.create",
  "monitoring.alertPolicies.delete",
  "monitoring.alertPolicies.get",
  "monitoring.alertPolicies.list",
  "monitoring.alertPolicies.update",
  "monitoring.dashboards.create",
  "monitoring.dashboards.delete",
  "monitoring.dashboards.get",
  "monitoring.dashboards.list",
  "monitoring.dashboards.update",
  "monitoring.groups.create",
  "monitoring.groups.delete",
  "monitoring.groups.get",
  "monitoring.groups.list",
  "monitoring.groups.update",
  "monitoring.metricDescriptors.create",
  "monitoring.metricDescriptors.delete",
  "monitoring.metricDescriptors.get",
  "monitoring.metricDescriptors.list",
  "monitoring.monitoredResourceDescriptors.get",
  "monitoring.monitoredResourceDescriptors.list",
  "monitoring.notificationChannelDescriptors.get",
  "monitoring.notificationChannelDescriptors.list",
  "monitoring.notificationChannels.create",
  "monitoring.notificationChannels.delete",
  "monitoring.notificationChannels.get",
  "monitoring.notificationChannels.getVerificationCode",
  "monitoring.notificationChannels.list",
  "monitoring.notificationChannels.sendVerificationCode",
  "monitoring.notificationChannels.update",
  "monitoring.notificationChannels.verify",
  "monitoring.publicWidgets.create",
  "monitoring.publicWidgets.delete",
  "monitoring.publicWidgets.get",
  "monitoring.publicWidgets.list",
  "monitoring.publicWidgets.update",
  "monitoring.timeSeries.create",
  "monitoring.timeSeries.list",
  "monitoring.uptimeCheckConfigs.create",
  "monitoring.uptimeCheckConfigs.delete",
  "monitoring.uptimeCheckConfigs.get",
  "monitoring.uptimeCheckConfigs.list",
  "monitoring.uptimeCheckConfigs.update",
  "orgpolicy.policy.get",
  "proximitybeacon.attachments.create",
  "proximitybeacon.attachments.delete",
  "proximitybeacon.attachments.get",
  "proximitybeacon.attachments.list",
  "proximitybeacon.beacons.attach",
  "proximitybeacon.beacons.create",
  "proximitybeacon.beacons.get",
  "proximitybeacon.beacons.getIamPolicy",
  "proximitybeacon.beacons.list",
  "proximitybeacon.beacons.setIamPolicy",
  "proximitybeacon.beacons.update",
  "proximitybeacon.namespaces.create",
  "proximitybeacon.namespaces.delete",
  "proximitybeacon.namespaces.get",
  "proximitybeacon.namespaces.getIamPolicy",
  "proximitybeacon.namespaces.list",
  "proximitybeacon.namespaces.setIamPolicy",
  "proximitybeacon.namespaces.update",
  "pubsub.snapshots.create",
  "pubsub.snapshots.delete",
  "pubsub.snapshots.get",
  "pubsub.snapshots.getIamPolicy",
  "pubsub.snapshots.list",
  "pubsub.snapshots.seek",
  "pubsub.snapshots.setIamPolicy",
  "pubsub.snapshots.update",
  "pubsub.subscriptions.consume",
  "pubsub.subscriptions.create",
  "pubsub.subscriptions.delete",
  "pubsub.subscriptions.get",
  "pubsub.subscriptions.getIamPolicy",
  "pubsub.subscriptions.list",
  "pubsub.subscriptions.setIamPolicy",
  "pubsub.subscriptions.update",
  "pubsub.topics.attachSubscription",
  "pubsub.topics.create",
  "pubsub.topics.delete",
  "pubsub.topics.get",
  "pubsub.topics.getIamPolicy",
  "pubsub.topics.list",
  "pubsub.topics.publish",
  "pubsub.topics.setIamPolicy",
  "pubsub.topics.update",
  "redis.instances.create",
  "redis.instances.delete",
  "redis.instances.get",
  "redis.instances.list",
  "redis.instances.update",
  "redis.locations.get",
  "redis.locations.list",
  "redis.operations.cancel",
  "redis.operations.delete",
  "redis.operations.get",
  "redis.operations.list",
  "reservepartner.portal.read",
  "reservepartner.portal.write",
  "resourcemanager.projects.createBillingAssignment",
  "resourcemanager.projects.delete",
  "resourcemanager.projects.deleteBillingAssignment",
  "resourcemanager.projects.get",
  "resourcemanager.projects.getIamPolicy",
  "resourcemanager.projects.list",
  "resourcemanager.projects.move",
  "resourcemanager.projects.setIamPolicy",
  "resourcemanager.projects.undelete",
  "resourcemanager.projects.update",
  "resourcemanager.projects.updateLiens",
  "runtimeconfig.configs.create",
  "runtimeconfig.configs.delete",
  "runtimeconfig.configs.get",
  "runtimeconfig.configs.getIamPolicy",
  "runtimeconfig.configs.list",
  "runtimeconfig.configs.setIamPolicy",
  "runtimeconfig.configs.update",
  "runtimeconfig.operations.get",
  "runtimeconfig.operations.list",
  "runtimeconfig.variables.create",
  "runtimeconfig.variables.delete",
  "runtimeconfig.variables.get",
  "runtimeconfig.variables.getIamPolicy",
  "runtimeconfig.variables.list",
  "runtimeconfig.variables.setIamPolicy",
  "runtimeconfig.variables.update",
  "runtimeconfig.variables.watch",
  "runtimeconfig.waiters.create",
  "runtimeconfig.waiters.delete",
  "runtimeconfig.waiters.get",
  "runtimeconfig.waiters.getIamPolicy",
  "runtimeconfig.waiters.list",
  "runtimeconfig.waiters.setIamPolicy",
  "runtimeconfig.waiters.update",
  "securitycenter.assets.get",
  "securitycenter.assets.getFieldNames",
  "securitycenter.assets.group",
  "securitycenter.assets.list",
  "securitycenter.assets.listAssetPropertyNames",
  "securitycenter.assets.runDiscovery",
  "securitycenter.assets.triggerDiscovery",
  "securitycenter.assets.update",
  "securitycenter.assetsecuritymarks.update",
  "securitycenter.configs.get",
  "securitycenter.configs.getIamPolicy",
  "securitycenter.configs.setIamPolicy",
  "securitycenter.configs.update",
  "securitycenter.findings.group",
  "securitycenter.findings.list",
  "securitycenter.findings.listFindingPropertyNames",
  "securitycenter.findings.setState",
  "securitycenter.findings.update",
  "securitycenter.findingsecuritymarks.update",
  "securitycenter.organizationsettings.get",
  "securitycenter.organizationsettings.update",
  "securitycenter.scans.get",
  "securitycenter.scans.list",
  "securitycenter.sources.get",
  "securitycenter.sources.getIamPolicy",
  "securitycenter.sources.list",
  "securitycenter.sources.setIamPolicy",
  "securitycenter.sources.update",
  "servicebroker.bindingoperations.get",
  "servicebroker.bindingoperations.list",
  "servicebroker.bindings.create",
  "servicebroker.bindings.delete",
  "servicebroker.bindings.get",
  "servicebroker.bindings.getIamPolicy",
  "servicebroker.bindings.list",
  "servicebroker.bindings.setIamPolicy",
  "servicebroker.catalogs.create",
  "servicebroker.catalogs.delete",
  "servicebroker.catalogs.get",
  "servicebroker.catalogs.getIamPolicy",
  "servicebroker.catalogs.list",
  "servicebroker.catalogs.setIamPolicy",
  "servicebroker.catalogs.validate",
  "servicebroker.instanceoperations.get",
  "servicebroker.instanceoperations.list",
  "servicebroker.instances.create",
  "servicebroker.instances.delete",
  "servicebroker.instances.get",
  "servicebroker.instances.getIamPolicy",
  "servicebroker.instances.list",
  "servicebroker.instances.setIamPolicy",
  "servicebroker.instances.update",
  "serviceconsumermanagement.consumers.get",
  "serviceconsumermanagement.quota.get",
  "serviceconsumermanagement.quota.update",
  "serviceconsumermanagement.tenancyu.addResource",
  "serviceconsumermanagement.tenancyu.create",
  "serviceconsumermanagement.tenancyu.delete",
  "serviceconsumermanagement.tenancyu.list",
  "serviceconsumermanagement.tenancyu.removeResource",
  "servicemanagement.consumerSettings.get",
  "servicemanagement.consumerSettings.getIamPolicy",
  "servicemanagement.consumerSettings.list",
  "servicemanagement.consumerSettings.setIamPolicy",
  "servicemanagement.consumerSettings.update",
  "servicemanagement.services.bind",
  "servicemanagement.services.check",
  "servicemanagement.services.create",
  "servicemanagement.services.delete",
  "servicemanagement.services.get",
  "servicemanagement.services.getIamPolicy",
  "servicemanagement.services.list",
  "servicemanagement.services.quota",
  "servicemanagement.services.report",
  "servicemanagement.services.setIamPolicy",
  "servicemanagement.services.update",
  "serviceusage.apiKeys.create",
  "serviceusage.apiKeys.delete",
  "serviceusage.apiKeys.get",
  "serviceusage.apiKeys.getProjectForKey",
  "serviceusage.apiKeys.list",
  "serviceusage.apiKeys.regenerate",
  "serviceusage.apiKeys.revert",
  "serviceusage.apiKeys.update",
  "serviceusage.operations.cancel",
  "serviceusage.operations.delete",
  "serviceusage.operations.get",
  "serviceusage.operations.list",
  "serviceusage.quotas.get",
  "serviceusage.quotas.update",
  "serviceusage.services.disable",
  "serviceusage.services.enable",
  "serviceusage.services.get",
  "serviceusage.services.list",
  "serviceusage.services.use",
  "source.repos.create",
  "source.repos.delete",
  "source.repos.get",
  "source.repos.getIamPolicy",
  "source.repos.getProjectConfig",
  "source.repos.list",
  "source.repos.setIamPolicy",
  "source.repos.update",
  "source.repos.updateProjectConfig",
  "source.repos.updateRepoConfig",
  "spanner.databaseOperations.cancel",
  "spanner.databaseOperations.delete",
  "spanner.databaseOperations.get",
  "spanner.databaseOperations.list",
  "spanner.databases.beginOrRollbackReadWriteTransaction",
  "spanner.databases.beginReadOnlyTransaction",
  "spanner.databases.create",
  "spanner.databases.drop",
  "spanner.databases.get",
  "spanner.databases.getDdl",
  "spanner.databases.getIamPolicy",
  "spanner.databases.list",
  "spanner.databases.read",
  "spanner.databases.select",
  "spanner.databases.setIamPolicy",
  "spanner.databases.update",
  "spanner.databases.updateDdl",
  "spanner.databases.write",
  "spanner.instanceConfigs.get",
  "spanner.instanceConfigs.list",
  "spanner.instanceOperations.cancel",
  "spanner.instanceOperations.delete",
  "spanner.instanceOperations.get",
  "spanner.instanceOperations.list",
  "spanner.instances.create",
  "spanner.instances.delete",
  "spanner.instances.get",
  "spanner.instances.getIamPolicy",
  "spanner.instances.list",
  "spanner.instances.setIamPolicy",
  "spanner.instances.update",
  "spanner.sessions.create",
  "spanner.sessions.delete",
  "spanner.sessions.get",
  "spanner.sessions.list",
  "stackdriver.projects.edit",
  "stackdriver.projects.get",
  "stackdriver.resourceMetadata.write",
  "storage.buckets.create",
  "storage.buckets.delete",
  "storage.buckets.list",
  "subscribewithgoogledeveloper.tools.get",
  "tpu.acceleratortypes.get",
  "tpu.acceleratortypes.list",
  "tpu.locations.get",
  "tpu.locations.list",
  "tpu.nodes.create",
  "tpu.nodes.delete",
  "tpu.nodes.get",
  "tpu.nodes.list",
  "tpu.nodes.reimage",
  "tpu.nodes.reset",
  "tpu.nodes.start",
  "tpu.nodes.stop",
  "tpu.operations.get",
  "tpu.operations.list",
  "tpu.tensorflowversions.get",
  "tpu.tensorflowversions.list"
 ],
 "stage": "GA",
 "etag": "AA=="
},
{
 "name": "roles/pubsub.publisher",
 "title": "Pub/Sub Publisher",
 "description": "Publish messages to a topic.",
 "includedPermissions": [
  "pubsub.topics.publish"
 ],
 "stage": "GA",
 "etag": "AA=="
},
{
 "name": "roles/resourcemanager.folderAdmin",
 "title": "Folder Admin",
 "description": "Access and administer a folder and all of its sub-resources.",
 "includedPermissions": [
  "orgpolicy.policy.get",
  "resourcemanager.folders.create",
  "resourcemanager.folders.delete",
  "resourcemanager.folders.get",
  "resourcemanager.folders.getIamPolicy",
  "resourcemanager.folders.list",
  "resourcemanager.folders.move",
  "resourcemanager.folders.setIamPolicy",
  "resourcemanager.folders.undelete",
  "resourcemanager.folders.update",
  "resourcemanager.projects.get",
  "resourcemanager.projects.getIamPolicy",
  "resourcemanager.projects.list",
  "resourcemanager.projects.move",
  "resourcemanager.projects.setIamPolicy"
 ],
 "stage": "GA",
 "etag": "AA=="
},
{
 "name": "roles/resourcemanager.organizationAdmin",
 "title": "Organization Administrator",
 "description": "Access to administer all resources belonging to the organization.",
 "includedPermissions": [
  "orgpolicy.policy.get",
  "resourcemanager.folders.get",
  "resourcemanager.folders.getIamPolicy",
  "resourcemanager.folders.list",
  "resourcemanager.folders.setIamPolicy",
  "resourcemanager.organizations.get",
  "resourcemanager.organizations.getIamPolicy",
  "resourcemanager.organizations.setIamPolicy",
  "resourcemanager.projects.get",
  "resourcemanager.projects.getIamPolicy",
  "resourcemanager.projects.list",
  "resourcemanager.projects.setIamPolicy"
 ],
 "stage": "GA",
 "etag": "AA=="
},
{
 "name": "roles/storage.legacyBucketOwner",
 "title": "Storage Legacy Bucket Owner",
 "description": "Read and write access to existing buckets with object listing/creation/deletion.",
 "includedPermissions": [
  "storage.buckets.get",
  "storage.buckets.getIamPolicy",
  "storage.buckets.setIamPolicy",
  "storage.buckets.update",
  "storage.objects.create",
  "storage.objects.delete",
  "storage.objects.list"
 ],
 "stage": "GA",
 "etag": "AA=="
},
{
 "name": "roles/storage.legacyBucketReader",
 "title": "Storage Legacy Bucket Reader",
 "description": "Read access to buckets with object listing.",
 "includedPermissions": [
  "storage.buckets.get",
  "storage.objects.list"
 ],
 "stage": "GA",
 "etag": "AA=="
},
]

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
