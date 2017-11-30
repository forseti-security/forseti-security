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
    ]
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
    "project3": {
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
                id=3, parent="folders/2", name="Folder 3")),
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
                parent_id="1")),
    PROJECT_ID_PREFIX + "4":
        json.loads(
            CRM_PROJECT_TEMPLATE.format(
                num=4,
                id="project4",
                name="Project 4",
                parent_type="folder",
                parent_id="3")),
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
            "projects": [CRM_GET_PROJECT[PROJECT_ID_PREFIX + "4"]]
        }]
    }
}

# Fields: id
CRM_PROJECT_IAM_POLICY_TEMPLATE = """
{{
 "version": 1,
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
 ]
}}
"""

CRM_FOLDER_IAM_POLICY = """
{
 "version": 1,
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
 "version": 1,
 "bindings": [
  {
   "role": "roles/resourcemanager.organizationAdmin",
   "members": [
    "user:a_user@forseti.test"
   ]
  }
 ]
}
"""

CRM_GET_IAM_POLICIES = {
    ORGANIZATION_ID: json.loads(CRM_ORG_IAM_POLICY),
    "folders/" + FOLDER_ID_PREFIX + "1": json.loads(CRM_FOLDER_IAM_POLICY),
    "folders/" + FOLDER_ID_PREFIX + "2": json.loads(CRM_FOLDER_IAM_POLICY),
    "folders/" + FOLDER_ID_PREFIX + "3": json.loads(CRM_FOLDER_IAM_POLICY),
    "project1": json.loads(CRM_PROJECT_IAM_POLICY_TEMPLATE.format(id=1)),
    "project2": json.loads(CRM_PROJECT_IAM_POLICY_TEMPLATE.format(id=2)),
    "project3": json.loads(CRM_PROJECT_IAM_POLICY_TEMPLATE.format(id=3)),
    "project4": json.loads(CRM_PROJECT_IAM_POLICY_TEMPLATE.format(id=4)),
}

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
    "project2": [
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
    "project1":
        json.loads(
            GCE_PROJECT_TEMPLATE.format(
                num=1, id="project1", projnum=PROJECT_ID_PREFIX + "1")),
    "project2":
        json.loads(
            GCE_PROJECT_TEMPLATE.format(
                num=2, id="project2", projnum=PROJECT_ID_PREFIX + "1")),
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
    "project1": [
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
    "project2": [
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
    "project1":
        json.loads(
            GCE_FIREWALL_TEMPLATE_IAP.format(
                id=1, project="project1", network="default")),
    "project2":
        json.loads(
            GCE_FIREWALL_TEMPLATE_DEFAULT.format(
                id=2, project="project2", network="default")),
}

# Fields: id, name, project, network, instance1, instance2, instance3
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
 "subnetwork": "https://www.googleapis.com/compute/v1/projects/{project}/regions/us-central1/subnetworks/{network}",
 "instance_urls": [
  "https://www.googleapis.com/compute/v1/projects/{project}/zones/us-central1-c/instances/{instance1}",
  "https://www.googleapis.com/compute/v1/projects/{project}/zones/us-central1-c/instances/{instance2}",
  "https://www.googleapis.com/compute/v1/projects/{project}/zones/us-central1-c/instances/{instance3}"
 ]
}}
"""

GCE_GET_INSTANCE_GROUPS = {
    "project1": [
        json.loads(
            GCE_INSTANCE_GROUPS_TEMPLATE.format(
                id=1,
                name="bs-1-ig-1",
                project="project1",
                network="default",
                instance1="iap_instance1",
                instance2="iap_instance2",
                instance3="iap_instance3")),
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
    "project1": [
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
    "project1": [
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

GCE_GET_INSTANCE_GROUP_MANAGERS = {
    "project1": [
        json.loads(
            INSTANCE_GROUP_MANAGER_TEMPLATE.format(
                id=1, name="igm-1", project="project1", template="it-1")),
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
    "project1": [
        json.loads(
            INSTANCE_TEMPLATES_TEMPLATE.format(
                id=1,
                name="it-1",
                project="project1",
                network="default",
                num=PROJECT_ID_PREFIX + "1")),
    ]
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

# Fields: name, num
BUCKET_ACLS_TEMPLATE = """
[
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
]
"""

GCS_GET_BUCKET_ACLS = {
    "bucket1": [
        json.loads(
            BUCKET_ACLS_TEMPLATE.format(
                name="bucket1", num=PROJECT_ID_PREFIX + "3")),
    ],
    "bucket2": [
        json.loads(
            BUCKET_ACLS_TEMPLATE.format(
                name="bucket2", num=PROJECT_ID_PREFIX + "4")),
    ]
}

BUCKET_IAM_TEMPLATE = """
{{
 "kind": "storage#policy",
 "resourceId": "projects/_/buckets/{name}",
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

GCS_GET_OBJECT_ACLS = {}

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
    ]
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
