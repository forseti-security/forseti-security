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

"""Test data for Compute GCP api responses."""

FAKE_PROJECT_ID = "project1"

LIST_BACKEND_SERVICES_RESPONSE_PAGE1 = """
{
 "kind": "compute#backendServiceAggregatedList",
 "id": "projects/project1/aggregated/backendServices",
 "items": {
  "global": {
   "backendServices": [
    {
      "kind": "compute#backendService",
      "id": "1234567890",
      "creationTimestamp": "2017-04-03T14:01:35.687-07:00",
      "name": "bs-1",
      "description": "bs-1-desc",
      "selfLink": "https://www.googleapis.com/compute/beta/projects/project1/global/backendServices/bs-1",
      "backends": [
          {
              "group": "https://www.googleapis.com/compute/beta/projects/project1/regions/us-central1/instanceGroups/bs-1-ig-1",
              "balancingMode": "UTILIZATION",
              "capacityScaler": 1.0
          }
      ],
      "healthChecks": [
          "https://www.googleapis.com/compute/beta/projects/project1/global/httpsHealthChecks/hc-1"
      ],
      "timeoutSec": 3610,
      "port": 8443,
      "protocol": "HTTPS",
      "portName": "https",
      "enableCDN": false,
      "sessionAffinity": "NONE",
      "affinityCookieTtlSec": 0,
      "loadBalancingScheme": "EXTERNAL",
      "connectionDraining": {
          "drainingTimeoutSec": 0
      }
    }
   ]
  },
  "regions/us-central1": {
   "warning": {
    "code": "NO_RESULTS_ON_PAGE",
    "message": "There are no results for scope 'regions/us-central1' on this page.",
    "data": [
     {
      "key": "scope",
      "value": "regions/us-central1"
     }
    ]
   }
  },
  "regions/europe-west1": {
   "warning": {
    "code": "NO_RESULTS_ON_PAGE",
    "message": "There are no results for scope 'regions/europe-west1' on this page.",
    "data": [
     {
      "key": "scope",
      "value": "regions/europe-west1"
     }
    ]
   }
  }
 },
 "selfLink": "https://www.googleapis.com/compute/beta/projects/project1/aggregated/backendServices",
 "nextPageToken": "123"
}
"""

LIST_BACKEND_SERVICES_RESPONSE_PAGE2 = """
{
 "kind": "compute#backendServiceAggregatedList",
 "id": "projects/project1/aggregated/backendServices",
 "items": {
  "global": {
   "backendServices": [
    {
      "kind": "compute#backendService",
      "id": "6071052922189792661",
      "creationTimestamp": "2017-05-12T11:14:18.559-07:00",
      "name": "iap-bs",
      "description": "",
      "selfLink": "https://www.googleapis.com/compute/beta/projects/project1/global/backendServices/iap-bs",
      "backends": [
          {
              "description": "",
              "group": "https://www.googleapis.com/compute/beta/projects/project1/zones/us-east1-c/instanceGroups/iap-ig",
              "balancingMode": "UTILIZATION",
              "maxUtilization": 0.8,
              "capacityScaler": 1.0
          }
      ],
      "healthChecks": [
          "https://www.googleapis.com/compute/beta/projects/project1/global/healthChecks/iap-hc"
      ],
      "timeoutSec": 30,
      "port": 80,
      "protocol": "HTTP",
      "portName": "http",
      "enableCDN": false,
      "sessionAffinity": "NONE",
      "affinityCookieTtlSec": 0,
      "loadBalancingScheme": "EXTERNAL",
      "connectionDraining": {
          "drainingTimeoutSec": 300
      },
      "iap": {
          "enabled": true,
          "oauth2ClientId": "foo",
          "oauth2ClientSecretSha256": "bar"
      }
    }
   ]
  },
  "regions/us-central1": {
   "warning": {
    "code": "NO_RESULTS_ON_PAGE",
    "message": "There are no results for scope 'regions/us-central1' on this page.",
    "data": [
     {
      "key": "scope",
      "value": "regions/us-central1"
     }
    ]
   }
  },
  "regions/europe-west1": {
   "warning": {
    "code": "NO_RESULTS_ON_PAGE",
    "message": "There are no results for scope 'regions/europe-west1' on this page.",
    "data": [
     {
      "key": "scope",
      "value": "regions/europe-west1"
     }
    ]
   }
  }
 },
 "selfLink": "https://www.googleapis.com/compute/beta/projects/project1/aggregated/backendServices"
}
"""

LIST_BACKEND_SERVICES_RESPONSES = [LIST_BACKEND_SERVICES_RESPONSE_PAGE1,
                                   LIST_BACKEND_SERVICES_RESPONSE_PAGE2]

EXPECTED_BACKEND_SERVICES_NAMES = ["bs-1", "iap-bs"]

DISKS_AGGREGATED_LIST = """
{
 "kind": "compute#diskAggregatedList",
 "id": "projects/project1/aggregated/disks",
 "items": {
  "zones/us-west1-a": {
   "warning": {
    "code": "NO_RESULTS_ON_PAGE",
    "message": "There are no results for scope 'zones/us-west1-a' on this page.",
    "data": [
     {
      "key": "scope",
      "value": "zones/us-west1-a"
     }
    ]
   }
  },
  "zones/us-west1-b": {
   "disks": [
    {
     "kind": "compute#disk",
     "id": "3201737339334630938",
     "creationTimestamp": "2017-08-07T10:18:45.802-07:00",
     "name": "instance-1",
     "sizeGb": "10",
     "zone": "https://www.googleapis.com/compute/v1/projects/project1/zones/us-west1-b",
     "status": "READY",
     "selfLink": "https://www.googleapis.com/compute/v1/projects/project1/zones/us-west1-b/disks/instance-1",
     "sourceImage": "https://www.googleapis.com/compute/v1/projects/debian-cloud/global/images/debian-9-stretch-v20170717",
     "sourceImageId": "4214972497302618486",
     "type": "https://www.googleapis.com/compute/v1/projects/project1/zones/us-west1-b/diskTypes/pd-standard",
     "licenses": [
      "https://www.googleapis.com/compute/v1/projects/debian-cloud/global/licenses/debian-9-stretch"
     ],
     "lastAttachTimestamp": "2017-08-07T10:18:45.806-07:00",
     "users": [
      "https://www.googleapis.com/compute/v1/projects/project1/zones/us-west1-b/instances/instance-1"
     ],
     "labelFingerprint": "42WmSpB8rSM="
    }
   ]
  },
  "zones/us-west1-c": {
   "warning": {
    "code": "NO_RESULTS_ON_PAGE",
    "message": "There are no results for scope 'zones/us-west1-c' on this page.",
    "data": [
     {
      "key": "scope",
      "value": "zones/us-west1-c"
     }
    ]
   }
  },
  "zones/southamerica-east1-a": {
   "warning": {
    "code": "NO_RESULTS_ON_PAGE",
    "message": "There are no results for scope 'zones/southamerica-east1-a' on this page.",
    "data": [
     {
      "key": "scope",
      "value": "zones/southamerica-east1-a"
     }
    ]
   }
  }
 },
 "selfLink": "https://www.googleapis.com/compute/v1/projects/project1/aggregated/disks"
}
"""

EXPECTED_DISKS_SELFLINKS = [
    ("https://www.googleapis.com/compute/v1/projects/project1/zones/us-west1-b/"
     "disks/instance-1")
]

FAKE_DISK_ZONE = "us-west1-b"

DISKS_LIST = """
{
 "kind": "compute#diskList",
 "id": "projects/project1/zones/us-west1-b/disks",
 "items": [
  {
   "kind": "compute#disk",
   "id": "3201737339334630938",
   "creationTimestamp": "2017-08-07T10:18:45.802-07:00",
   "name": "instance-1",
   "sizeGb": "10",
   "zone": "https://www.googleapis.com/compute/v1/projects/project1/zones/us-west1-b",
   "status": "READY",
   "selfLink": "https://www.googleapis.com/compute/v1/projects/project1/zones/us-west1-b/disks/instance-1",
   "sourceImage": "https://www.googleapis.com/compute/v1/projects/debian-cloud/global/images/debian-9-stretch-v20170717",
   "sourceImageId": "4214972497302618486",
   "type": "https://www.googleapis.com/compute/v1/projects/project1/zones/us-west1-b/diskTypes/pd-standard",
   "licenses": [
    "https://www.googleapis.com/compute/v1/projects/debian-cloud/global/licenses/debian-9-stretch"
   ],
   "lastAttachTimestamp": "2017-08-07T10:18:45.806-07:00",
   "users": [
    "https://www.googleapis.com/compute/v1/projects/project1/zones/us-west1-b/instances/instance-1"
   ],
   "labelFingerprint": "42WmSpB8rSM="
  }
 ],
 "selfLink": "https://www.googleapis.com/compute/v1/projects/project1/zones/us-west1-b/disks"
}
"""


FORWARDING_RULES_AGGREGATED_LIST = """
{
 "kind": "compute#forwardingRuleAggregatedList",
 "id": "projects/project1/aggregated/forwardingRules",
 "items": {
  "global": {
   "warning": {
    "code": "NO_RESULTS_ON_PAGE",
    "message": "There are no results for scope 'global' on this page.",
    "data": [
     {
      "key": "scope",
      "value": "global"
     }
    ]
   }
  },
  "regions/europe-west1": {
   "warning": {
    "code": "NO_RESULTS_ON_PAGE",
    "message": "There are no results for scope 'regions/europe-west1' on this page.",
    "data": [
     {
      "key": "scope",
      "value": "regions/europe-west1"
     }
    ]
   }
  },
  "regions/us-central1": {
   "forwardingRules": [
    {
      "kind": "compute#forwardingRule",
      "description": "",
      "IPAddress": "10.10.10.1",
      "region": "https://www.googleapis.com/compute/v1/projects/project1/regions/us-central1",
      "loadBalancingScheme": "EXTERNAL",
      "target": "https://www.googleapis.com/compute/v1/projects/project1/regions/us-central1/targetPools/project1-pool",
      "portRange": "80-80",
      "IPProtocol": "TCP",
      "creationTimestamp": "2017-05-05T12:00:01.000-07:00",
      "id": "111111111111",
      "selfLink": "https://www.googleapis.com/compute/v1/projects/project1/regions/us-central1/forwardingRules/project1-rule",
      "name": "project1-rule"
    }
   ]
  }
 },
 "selfLink": "https://www.googleapis.com/compute/v1/projects/project1/aggregated/forwardingRules"
}
"""

FORWARDING_RULES_LIST = """
{
 "kind": "compute#forwardingRuleList",
 "id": "projects/project1/regions/us-central1/forwardingRules",
 "items": [
  {
    "kind": "compute#forwardingRule",
    "description": "",
    "IPAddress": "10.10.10.1",
    "region": "https://www.googleapis.com/compute/v1/projects/project1/regions/us-central1",
    "loadBalancingScheme": "EXTERNAL",
    "target": "https://www.googleapis.com/compute/v1/projects/project1/regions/us-central1/targetPools/project1-pool",
    "portRange": "80-80",
    "IPProtocol": "TCP",
    "creationTimestamp": "2017-05-05T12:00:01.000-07:00",
    "id": "111111111111",
    "selfLink": "https://www.googleapis.com/compute/v1/projects/project1/regions/us-central1/forwardingRules/project1-rule",
    "name": "project1-rule"
  }
 ],
 "selfLink": "https://www.googleapis.com/compute/v1/projects/project1/regions/us-central1/forwardingRules"
}
"""

FAKE_FORWARDING_RULE_REGION = "us-central1"
EXPECTED_FORWARDING_RULE_NAMES = ["project1-rule"]


FIREWALLS_LIST_PAGE1 = """
{
 "kind": "compute#firewallList",
 "id": "projects/project1/global/firewalls",
 "items": [
  {
   "kind": "compute#firewall",
   "id": "12345",
   "creationTimestamp": "2017-05-04T16:23:00.568-07:00",
   "network": "https://www.googleapis.com/compute/beta/projects/project1/global/networks/default1",
   "priority": 1000,
   "sourceRanges": ["0.0.0.0/0"],
   "description": "Allow ICMP from anywhere",
   "allowed": [
    {
     "IPProtocol": "icmp"
    }
   ],
   "name": "default-allow-icmp",
   "direction": "INGRESS",
   "selfLink": "https://www.googleapis.com/compute/beta/projects/project1/global/firewalls/default-allow-icmp"
  },
  {
   "kind": "compute#firewall",
   "id": "12346",
   "creationTimestamp": "2017-05-04T16:23:00.568-07:00",
   "network": "https://www.googleapis.com/compute/beta/projects/project1/global/networks/default1",
   "priority": 1000,
   "sourceRanges": ["0.0.0.0/0"],
   "description": "Allow RDP from anywhere",
   "allowed": [
    {
     "IPProtocol": "tcp",
     "ports": ["3389"]
    }
   ],
   "name": "default-allow-rdp",
   "direction": "INGRESS",
   "selfLink": "https://www.googleapis.com/compute/beta/projects/project1/global/firewalls/default-allow-rdp"
  }
 ],
 "nextPageToken": "123",
 "selfLink": "https://www.googleapis.com/compute/beta/projects/project1/global/firewalls"
}
"""

FIREWALLS_LIST_PAGE2 = """
{
 "kind": "compute#firewallList",
 "id": "projects/project1/global/firewalls",
 "items": [
  {
   "kind": "compute#firewall",
   "id": "12345",
   "creationTimestamp": "2017-05-04T16:23:00.568-07:00",
   "network": "https://www.googleapis.com/compute/beta/projects/project1/global/networks/default1",
   "priority": 1000,
   "sourceRanges": ["0.0.0.0/0"],
   "description": "Allow SSH from anywhere",
   "allowed": [
    {
     "IPProtocol": "tcp",
     "ports": ["22"]
    }
   ],
   "name": "default-allow-ssh",
   "direction": "INGRESS",
   "selfLink": "https://www.googleapis.com/compute/beta/projects/project1/global/firewalls/default-allow-ssh"
  },
  {
   "kind": "compute#firewall",
   "id": "12346",
   "creationTimestamp": "2017-05-04T16:23:00.568-07:00",
   "network": "https://www.googleapis.com/compute/beta/projects/project1/global/networks/default1",
   "priority": 1000,
   "sourceRanges": ["10.0.0.0/8"],
   "description": "Allow internal traffic on the default network.",
   "allowed": [
    {
     "IPProtocol": "udp",
     "ports": ["1-65535"]
    },
    {
     "IPProtocol": "tcp",
     "ports": ["1-65535"]
    },
    {
     "IPProtocol": "icmp"
    }
   ],
   "name": "default-allow-internal",
   "direction": "INGRESS",
   "selfLink": "https://www.googleapis.com/compute/beta/projects/project1/global/firewalls/default-allow-internal"
  }
 ],
 "selfLink": "https://www.googleapis.com/compute/beta/projects/project1/global/firewalls"
}
"""

LIST_FIREWALLS_RESPONSES = [FIREWALLS_LIST_PAGE1, FIREWALLS_LIST_PAGE2]

EXPECTED_FIREWALL_NAMES = ["default-allow-icmp", "default-allow-rdp",
                           "default-allow-ssh", "default-allow-internal"]

LIST_IMAGES = """
{
 "kind": "compute#imageList",
 "id": "projects/project1/global/images",
 "items": [
  {
   "kind": "compute#image",
   "id": "1234",
   "creationTimestamp": "2017-11-15T21:59:58.627-08:00",
   "name": "centos-6-custom-v20171116",
   "description": "Custom CentOS 6 built on 20171116",
   "sourceType": "RAW",
   "deprecated": {
    "state": "DEPRECATED",
    "replacement": "https://www.googleapis.com/compute/v1/projects/project1/global/images/centos-6-custom-v20171208"
   },
   "status": "READY",
   "archiveSizeBytes": "688350464",
   "diskSizeGb": "10",
   "sourceDisk": "https://www.googleapis.com/compute/v1/projects/project1/zones/us-central1-b/disks/disk-install-centos-6-custom-dz0wt",
   "sourceDiskId": "2345",
   "licenses": [
    "https://www.googleapis.com/compute/v1/projects/centos-cloud/global/licenses/centos-6"
   ],
   "family": "centos-6-custom",
   "selfLink": "https://www.googleapis.com/compute/v1/projects/project1/global/images/centos-6-custom-v20171116",
   "labelFingerprint": "42WmSpB8rSM=",
   "guestOsFeatures": [
    {
     "type": "VIRTIO_SCSI_MULTIQUEUE"
    }
   ]
  },
  {
   "kind": "compute#image",
   "id": "3456",
   "creationTimestamp": "2017-12-07T16:19:13.482-08:00",
   "name": "centos-6-custom-v20171208",
   "description": "Custom CentOS 6 built on 20171208",
   "sourceType": "RAW",
   "status": "READY",
   "archiveSizeBytes": "788880064",
   "diskSizeGb": "10",
   "sourceDisk": "https://www.googleapis.com/compute/v1/projects/project1/zones/us-central1-b/disks/disk-install-centos-6-custom-62bzs",
   "sourceDiskId": "5678",
   "licenses": [
    "https://www.googleapis.com/compute/v1/projects/centos-cloud/global/licenses/centos-6"
   ],
   "family": "centos-6-custom",
   "selfLink": "https://www.googleapis.com/compute/v1/projects/project1/global/images/centos-6-custom-v20171208",
   "labelFingerprint": "42WmSpB8rSM=",
   "guestOsFeatures": [
    {
     "type": "VIRTIO_SCSI_MULTIQUEUE"
    }
   ]
  }
 ],
 "selfLink": "https://www.googleapis.com/compute/v1/projects/project1/global/images"
}
"""

EXPECTED_IMAGE_NAMES = ["centos-6-custom-v20171116",
                        "centos-6-custom-v20171208"]

FAKE_IMAGE_NAME = "centos-6-custom-v20171208"

GET_IMAGE = """
{
 "kind": "compute#image",
 "id": "3456",
 "creationTimestamp": "2017-12-07T16:19:13.482-08:00",
 "name": "centos-6-custom-v20171208",
 "description": "Custom CentOS 6 built on 20171208",
 "sourceType": "RAW",
 "status": "READY",
 "archiveSizeBytes": "788880064",
 "diskSizeGb": "10",
 "sourceDisk": "https://www.googleapis.com/compute/v1/projects/project1/zones/us-central1-b/disks/disk-install-centos-6-custom-62bzs",
 "sourceDiskId": "5678",
 "licenses": [
  "https://www.googleapis.com/compute/v1/projects/centos-cloud/global/licenses/centos-6"
 ],
 "family": "centos-6-custom",
 "selfLink": "https://www.googleapis.com/compute/v1/projects/project1/global/images/centos-6-custom-v20171208",
 "labelFingerprint": "42WmSpB8rSM=",
 "guestOsFeatures": [
  {
   "type": "VIRTIO_SCSI_MULTIQUEUE"
  }
 ]
}
"""

INSTANCES_AGGREGATED_LIST = """
{
 "kind": "compute#instanceAggregatedList",
 "id": "projects/project1/aggregated/instances",
 "items": {
  "zones/us-central1-a": {
   "warning": {
    "code": "NO_RESULTS_ON_PAGE",
    "message": "There are no results for scope 'zones/us-central1-a' on this page.",
    "data": [
     {
      "key": "scope",
      "value": "zones/us-central1-a"
     }
    ]
   }
  },
  "zones/us-central1-b": {
   "warning": {
    "code": "NO_RESULTS_ON_PAGE",
    "message": "There are no results for scope 'zones/us-central1-b' on this page.",
    "data": [
     {
      "key": "scope",
      "value": "zones/us-central1-b"
     }
    ]
   }
  },
  "zones/us-central1-c": {
   "instances": [
    {
     "kind": "compute#instance",
     "id": "1234567890",
     "creationTimestamp": "2017-05-26T22:08:11.094-07:00",
     "name": "iap-ig-79bj",
     "tags": {
      "items": [
       "iap-tag"
      ],
      "fingerprint": "gilEhx3hEXk="
     },
     "machineType": "https://www.googleapis.com/compute/v1/projects/project1/zones/us-central1-c/machineTypes/f1-micro",
     "status": "RUNNING",
     "zone": "https://www.googleapis.com/compute/v1/projects/project1/zones/us-central1-c",
     "canIpForward": false,
     "networkInterfaces": [
      {
       "kind": "compute#networkInterface",
       "network": "https://www.googleapis.com/compute/v1/projects/project1/global/networks/default1",
       "subnetwork": "https://www.googleapis.com/compute/v1/projects/project1/regions/us-central1/subnetworks/default1",
       "networkIP": "10.128.0.2",
       "name": "nic0",
       "accessConfigs": [
        {
         "kind": "compute#accessConfig",
         "type": "ONE_TO_ONE_NAT",
         "name": "External NAT",
         "natIP": "104.198.131.130"
        }
       ]
      }
     ],
     "disks": [
      {
       "kind": "compute#attachedDisk",
       "type": "PERSISTENT",
       "mode": "READ_WRITE",
       "source": "https://www.googleapis.com/compute/v1/projects/project1/zones/us-central1-c/disks/iap-ig-79bj",
       "deviceName": "iap-it-1",
       "index": 0,
       "boot": true,
       "autoDelete": true,
       "licenses": [
        "https://www.googleapis.com/compute/v1/projects/debian-cloud/global/licenses/debian-8-jessie"
       ],
       "interface": "SCSI"
      }
     ],
     "metadata": {
     "kind": "compute#metadata",
     "fingerprint": "3MpZMMvDTyo=",
     "items": [
      {
       "key": "instance-template",
       "value": "projects/1111111/global/instanceTemplates/iap-it-1"
      },
      {
       "key": "created-by",
       "value": "projects/1111111/zones/us-central1-c/instanceGroupManagers/iap-ig"
      }
     ]
     },
     "serviceAccounts": [
      {
       "email": "1111111-compute@developer.gserviceaccount.com",
       "scopes": [
        "https://www.googleapis.com/auth/devstorage.read_only",
        "https://www.googleapis.com/auth/logging.write",
        "https://www.googleapis.com/auth/monitoring.write",
        "https://www.googleapis.com/auth/servicecontrol",
        "https://www.googleapis.com/auth/service.management.readonly",
        "https://www.googleapis.com/auth/trace.append"
       ]
      }
     ],
     "selfLink": "https://www.googleapis.com/compute/v1/projects/project1/zones/us-central1-c/instances/iap-ig-79bj",
     "scheduling": {
      "onHostMaintenance": "MIGRATE",
      "automaticRestart": true,
      "preemptible": false
     },
     "cpuPlatform": "Intel Haswell"
    }
   ]
  }
 },
 "selfLink": "https://www.googleapis.com/compute/v1/projects/project1/aggregated/instances"
}
"""

INSTANCES_LIST = """
{
 "kind": "compute#instanceList",
 "id": "projects/project1/zones/us-central1-c/instances",
 "items": [
  {
   "kind": "compute#instance",
   "id": "1234567890",
   "creationTimestamp": "2017-05-26T22:08:11.094-07:00",
   "name": "iap-ig-79bj",
   "tags": {
    "items": [
     "iap-tag"
    ],
    "fingerprint": "gilEhx3hEXk="
   },
   "machineType": "https://www.googleapis.com/compute/v1/projects/project1/zones/us-central1-c/machineTypes/f1-micro",
   "status": "RUNNING",
   "zone": "https://www.googleapis.com/compute/v1/projects/project1/zones/us-central1-c",
   "canIpForward": false,
   "networkInterfaces": [
    {
     "kind": "compute#networkInterface",
     "network": "https://www.googleapis.com/compute/v1/projects/project1/global/networks/default1",
     "subnetwork": "https://www.googleapis.com/compute/v1/projects/project1/regions/us-central1/subnetworks/default1",
     "networkIP": "10.128.0.2",
     "name": "nic0",
     "accessConfigs": [
      {
       "kind": "compute#accessConfig",
       "type": "ONE_TO_ONE_NAT",
       "name": "External NAT",
       "natIP": "104.198.131.130"
      }
     ]
    }
   ],
   "disks": [
    {
     "kind": "compute#attachedDisk",
     "type": "PERSISTENT",
     "mode": "READ_WRITE",
     "source": "https://www.googleapis.com/compute/v1/projects/project1/zones/us-central1-c/disks/iap-ig-79bj",
     "deviceName": "iap-it-1",
     "index": 0,
     "boot": true,
     "autoDelete": true,
     "licenses": [
      "https://www.googleapis.com/compute/v1/projects/debian-cloud/global/licenses/debian-8-jessie"
     ],
     "interface": "SCSI"
    }
   ],
   "metadata": {
   "kind": "compute#metadata",
   "fingerprint": "3MpZMMvDTyo=",
   "items": [
    {
     "key": "instance-template",
     "value": "projects/1111111/global/instanceTemplates/iap-it-1"
    },
    {
     "key": "created-by",
     "value": "projects/1111111/zones/us-central1-c/instanceGroupManagers/iap-ig"
    }
   ]
   },
   "serviceAccounts": [
    {
     "email": "1111111-compute@developer.gserviceaccount.com",
     "scopes": [
      "https://www.googleapis.com/auth/devstorage.read_only",
      "https://www.googleapis.com/auth/logging.write",
      "https://www.googleapis.com/auth/monitoring.write",
      "https://www.googleapis.com/auth/servicecontrol",
      "https://www.googleapis.com/auth/service.management.readonly",
      "https://www.googleapis.com/auth/trace.append"
     ]
    }
   ],
   "selfLink": "https://www.googleapis.com/compute/v1/projects/project1/zones/us-central1-c/instances/iap-ig-79bj",
   "scheduling": {
    "onHostMaintenance": "MIGRATE",
    "automaticRestart": true,
    "preemptible": false
   },
   "cpuPlatform": "Intel Haswell"
  }
 ],
 "selfLink": "https://www.googleapis.com/compute/v1/projects/project1/zones/us-central1-c/instances"
}
"""

FAKE_INSTANCE_ZONE = "us-central1-c"
EXPECTED_INSTANCE_NAMES = ["iap-ig-79bj"]

INSTANCE_GROUP_LIST_INSTANCES = """
{
 "items": [
  {
   "instance": "https://www.googleapis.com/compute/v1/projects/project1/zones/us-central1-c/instances/iap-ig-79bj"
  }
 ]
}
"""

REGION_INSTANCE_GROUP_LIST_INSTANCES = """
{
 "items": [
  {
   "instance": "https://www.googleapis.com/compute/v1/projects/project1/zones/us-central1-b/instances/iap-ig-1c4k"
  },
  {
   "instance": "https://www.googleapis.com/compute/v1/projects/project1/zones/us-central1-f/instances/iap-ig-9jvq"
  },
  {
   "instance": "https://www.googleapis.com/compute/v1/projects/project1/zones/us-central1-c/instances/iap-ig-dc7w"
  }
 ]
}
"""

FAKE_INSTANCE_GROUP = "iap-ig"
FAKE_INSTANCE_GROUP_REGION = "us-central1"

EXPECTED_INSTANCE_GROUP_ZONE_URLS = [
    ("https://www.googleapis.com/compute/v1/projects/project1/zones/"
     "us-central1-c/instances/iap-ig-79bj")]

EXPECTED_INSTANCE_GROUP_REGION_URLS = [
    ("https://www.googleapis.com/compute/v1/projects/project1/zones/"
     "us-central1-b/instances/iap-ig-1c4k"),
    ("https://www.googleapis.com/compute/v1/projects/project1/zones/"
     "us-central1-f/instances/iap-ig-9jvq"),
    ("https://www.googleapis.com/compute/v1/projects/project1/zones/"
     "us-central1-c/instances/iap-ig-dc7w")]

INSTANCE_GROUPS_AGGREGATED_LIST = """
{
 "kind": "compute#instanceGroupAggregatedList",
 "id": "projects/project1/aggregated/instanceGroups",
 "items": {
  "regions/us-central1": {
   "instanceGroups": [
    {
     "kind": "compute#instanceGroup",
     "id": "987654321",
     "creationTimestamp": "2017-08-24T11:10:06.771-07:00",
     "name": "iap-ig-region",
     "description": "This instance group is controlled by Regional Instance Group Manager 'iap-ig-region'. To modify instances in this group, use the Regional Instance Group Manager API: https://cloud.google.com/compute/docs/reference/latest/instanceGroupManagers",
     "network": "https://www.googleapis.com/compute/v1/projects/project1/global/networks/default1",
     "fingerprint": "42WmSpB8rSM=",
     "selfLink": "https://www.googleapis.com/compute/v1/projects/project1/regions/us-central1/instanceGroups/iap-ig-region",
     "size": 3,
     "region": "https://www.googleapis.com/compute/v1/projects/project1/regions/us-central1",
     "subnetwork": "https://www.googleapis.com/compute/v1/projects/project1/regions/us-central1/subnetworks/default1"
    }
   ]
  },
  "regions/europe-west1": {
   "warning": {
    "code": "NO_RESULTS_ON_PAGE",
    "message": "There are no results for scope 'regions/europe-west1' on this page.",
    "data": [
     {
      "key": "scope",
      "value": "regions/europe-west1"
     }
    ]
   }
  },
  "zones/us-central1-a": {
   "warning": {
    "code": "NO_RESULTS_ON_PAGE",
    "message": "There are no results for scope 'zones/us-central1-a' on this page.",
    "data": [
     {
      "key": "scope",
      "value": "zones/us-central1-a"
     }
    ]
   }
  },
  "zones/us-central1-b": {
   "warning": {
    "code": "NO_RESULTS_ON_PAGE",
    "message": "There are no results for scope 'zones/us-central1-b' on this page.",
    "data": [
     {
      "key": "scope",
      "value": "zones/us-central1-b"
     }
    ]
   }
  },
  "zones/us-central1-c": {
   "instanceGroups": [
    {
     "kind": "compute#instanceGroup",
     "id": "1234567890",
     "creationTimestamp": "2017-08-24T11:04:08.037-07:00",
     "name": "iap-ig",
     "description": "This instance group is controlled by Instance Group Manager 'iap-ig'. To modify instances in this group, use the Instance Group Manager API: https://cloud.google.com/compute/docs/reference/latest/instanceGroupManagers",
     "network": "https://www.googleapis.com/compute/v1/projects/project1/global/networks/default1",
     "fingerprint": "42WmSpB8rSM=",
     "zone": "https://www.googleapis.com/compute/v1/projects/project1/zones/us-central1-c",
     "selfLink": "https://www.googleapis.com/compute/v1/projects/project1/zones/us-central1-c/instanceGroups/iap-ig",
     "size": 1,
     "subnetwork": "https://www.googleapis.com/compute/v1/projects/project1/regions/us-central1/subnetworks/default1"
    }
   ]
  },
  "zones/us-central1-f": {
   "warning": {
    "code": "NO_RESULTS_ON_PAGE",
    "message": "There are no results for scope 'zones/us-central1-f' on this page.",
    "data": [
     {
      "key": "scope",
      "value": "zones/us-central1-f"
     }
    ]
   }
  }
 },
 "selfLink": "https://www.googleapis.com/compute/v1/projects/project1/aggregated/instanceGroups"
}
"""

EXPECTED_INSTANCE_GROUP_NAMES = ["iap-ig", "iap-ig-region"]
EXPECTED_INSTANCE_GROUP_URLS = [EXPECTED_INSTANCE_GROUP_ZONE_URLS,
                                EXPECTED_INSTANCE_GROUP_REGION_URLS]

INSTANCE_TEMPLATES_LIST = """
{
 "kind": "compute#instanceTemplateList",
 "id": "projects/project1/global/instanceTemplates",
 "items": [
  {
   "kind": "compute#instanceTemplate",
   "id": "599361064932783991",
   "creationTimestamp": "2017-05-26T22:07:36.275-07:00",
   "name": "iap-it-1",
   "description": "",
   "properties": {
    "tags": {
     "items": [
      "iap-tag"
     ]
    },
    "machineType": "f1-micro",
    "canIpForward": false,
    "networkInterfaces": [
     {
      "kind": "compute#networkInterface",
      "network": "https://www.googleapis.com/compute/v1/projects/project1/global/networks/default1",
      "accessConfigs": [
       {
        "kind": "compute#accessConfig",
        "type": "ONE_TO_ONE_NAT",
        "name": "External NAT"
       }
      ]
     }
    ],
    "disks": [
     {
      "kind": "compute#attachedDisk",
      "type": "PERSISTENT",
      "mode": "READ_WRITE",
      "deviceName": "iap-it-1",
      "boot": true,
      "initializeParams": {
       "sourceImage": "projects/debian-cloud/global/images/debian-8-jessie-v20170523",
       "diskSizeGb": "10",
       "diskType": "pd-standard"
      },
      "autoDelete": true
     }
    ],
    "metadata": {
     "kind": "compute#metadata",
     "fingerprint": "Ab2_F_dLE3A="
    },
    "serviceAccounts": [
     {
      "email": "600687511243-compute@developer.gserviceaccount.com",
      "scopes": [
       "https://www.googleapis.com/auth/devstorage.read_only",
       "https://www.googleapis.com/auth/logging.write",
       "https://www.googleapis.com/auth/monitoring.write",
       "https://www.googleapis.com/auth/servicecontrol",
       "https://www.googleapis.com/auth/service.management.readonly",
       "https://www.googleapis.com/auth/trace.append"
      ]
     }
    ],
    "scheduling": {
     "onHostMaintenance": "MIGRATE",
     "automaticRestart": true,
     "preemptible": false
    }
   },
   "selfLink": "https://www.googleapis.com/compute/v1/projects/project1/global/instanceTemplates/iap-it-1"
  }
 ],
 "selfLink": "https://www.googleapis.com/compute/v1/projects/project1/global/instanceTemplates"
}
"""

EXPECTED_INSTANCE_TEMPLATE_NAMES = ["iap-it-1"]

INSTANCE_GROUP_MANAGERS_AGGREGATED_LIST = """
{
 "kind": "compute#instanceGroupManagerAggregatedList",
 "id": "projects/project1/aggregated/instanceGroupManagers",
 "items": {
  "regions/us-central1": {
   "instanceGroupManagers": [
    {
     "kind": "compute#instanceGroupManager",
     "id": "1289488281338292369",
     "creationTimestamp": "2017-08-24T11:10:06.770-07:00",
     "name": "iap-ig-region",
     "region": "https://www.googleapis.com/compute/v1/projects/project1/regions/us-central1",
     "instanceTemplate": "https://www.googleapis.com/compute/v1/projects/project1/global/instanceTemplates/iap-it-1",
     "instanceGroup": "https://www.googleapis.com/compute/v1/projects/project1/regions/us-central1/instanceGroups/iap-ig-region",
     "baseInstanceName": "iap-ig-region",
     "fingerprint": "NmHIa6VPc3Y=",
     "currentActions": {
      "none": 3,
      "creating": 0,
      "creatingWithoutRetries": 0,
      "recreating": 0,
      "deleting": 0,
      "abandoning": 0,
      "restarting": 0,
      "refreshing": 0
     },
     "targetSize": 3,
     "selfLink": "https://www.googleapis.com/compute/v1/projects/project1/regions/us-central1/instanceGroupManagers/iap-ig-region"
    }
   ]
  },
  "zones/us-central1-a": {
   "warning": {
    "code": "NO_RESULTS_ON_PAGE",
    "message": "There are no results for scope 'zones/us-central1-a' on this page.",
    "data": [
     {
      "key": "scope",
      "value": "zones/us-central1-a"
     }
    ]
   }
  },
  "zones/us-central1-b": {
   "warning": {
    "code": "NO_RESULTS_ON_PAGE",
    "message": "There are no results for scope 'zones/us-central1-b' on this page.",
    "data": [
     {
      "key": "scope",
      "value": "zones/us-central1-b"
     }
    ]
   }
  },
  "zones/us-central1-c": {
   "instanceGroupManagers": [
    {
     "kind": "compute#instanceGroupManager",
     "id": "1532459550555580553",
     "creationTimestamp": "2017-05-26T13:56:06.149-07:00",
     "name": "iap-ig",
     "zone": "https://www.googleapis.com/compute/v1/projects/project1/zones/us-central1-c",
     "instanceTemplate": "https://www.googleapis.com/compute/v1/projects/project1/global/instanceTemplates/iap-it-1",
     "instanceGroup": "https://www.googleapis.com/compute/v1/projects/project1/zones/us-central1-c/instanceGroups/iap-ig",
     "baseInstanceName": "iap-ig",
     "fingerprint": "OYowLtDCpv8=",
     "currentActions": {
      "none": 1,
      "creating": 0,
      "creatingWithoutRetries": 0,
      "recreating": 0,
      "deleting": 0,
      "abandoning": 0,
      "restarting": 0,
      "refreshing": 0
     },
     "targetSize": 1,
     "selfLink": "https://www.googleapis.com/compute/v1/projects/project1/zones/us-central1-c/instanceGroupManagers/iap-ig",
     "namedPorts": [
      {
       "name": "http",
       "port": 80
      }
     ]
    }
   ]
  },
  "zones/us-central1-f": {
   "warning": {
    "code": "NO_RESULTS_ON_PAGE",
    "message": "There are no results for scope 'zones/us-central1-f' on this page.",
    "data": [
     {
      "key": "scope",
      "value": "zones/us-central1-f"
     }
    ]
   }
  }
 },
 "selfLink": "https://www.googleapis.com/compute/v1/projects/project1/aggregated/instanceGroupManagers"
}
"""

EXPECTED_INSTANCE_GROUP_MANAGER_NAMES = ["iap-ig", "iap-ig-region"]

GET_PROJECT_RESPONSE = """
{
 "kind": "compute#project",
 "id": "1111111",
 "creationTimestamp": "2016-02-25T14:01:23.140-08:00",
 "name": "project1",
 "commonInstanceMetadata": {
  "kind": "compute#metadata",
  "fingerprint": "ABC",
  "items": [
   {
    "key": "some-key",
    "value": "some-value"
   }
  ]
 },
 "quotas": [
  {
   "metric": "SNAPSHOTS",
   "limit": 1000.0,
   "usage": 0.0
  },
  {
   "metric": "NETWORKS",
   "limit": 5.0,
   "usage": 1.0
  },
  {
   "metric": "FIREWALLS",
   "limit": 100.0,
   "usage": 9.0
  },
  {
   "metric": "IMAGES",
   "limit": 100.0,
   "usage": 0.0
  },
  {
   "metric": "STATIC_ADDRESSES",
   "limit": 8.0,
   "usage": 0.0
  },
  {
   "metric": "ROUTES",
   "limit": 200.0,
   "usage": 12.0
  },
  {
   "metric": "FORWARDING_RULES",
   "limit": 15.0,
   "usage": 1.0
  },
  {
   "metric": "TARGET_POOLS",
   "limit": 50.0,
   "usage": 1.0
  },
  {
   "metric": "HEALTH_CHECKS",
   "limit": 50.0,
   "usage": 1.0
  },
  {
   "metric": "IN_USE_ADDRESSES",
   "limit": 23.0,
   "usage": 1.0
  },
  {
   "metric": "TARGET_INSTANCES",
   "limit": 50.0,
   "usage": 0.0
  },
  {
   "metric": "TARGET_HTTP_PROXIES",
   "limit": 10.0,
   "usage": 0.0
  },
  {
   "metric": "URL_MAPS",
   "limit": 10.0,
   "usage": 0.0
  },
  {
   "metric": "BACKEND_SERVICES",
   "limit": 5.0,
   "usage": 0.0
  },
  {
   "metric": "INSTANCE_TEMPLATES",
   "limit": 100.0,
   "usage": 0.0
  },
  {
   "metric": "TARGET_VPN_GATEWAYS",
   "limit": 5.0,
   "usage": 0.0
  },
  {
   "metric": "VPN_TUNNELS",
   "limit": 10.0,
   "usage": 0.0
  },
  {
   "metric": "BACKEND_BUCKETS",
   "limit": 3.0,
   "usage": 0.0
  },
  {
   "metric": "ROUTERS",
   "limit": 10.0,
   "usage": 0.0
  },
  {
   "metric": "TARGET_SSL_PROXIES",
   "limit": 10.0,
   "usage": 0.0
  },
  {
   "metric": "TARGET_HTTPS_PROXIES",
   "limit": 10.0,
   "usage": 0.0
  },
  {
   "metric": "SSL_CERTIFICATES",
   "limit": 10.0,
   "usage": 0.0
  },
  {
   "metric": "SUBNETWORKS",
   "limit": 100.0,
   "usage": 11.0
  },
  {
   "metric": "TARGET_TCP_PROXIES",
   "limit": 10.0,
   "usage": 0.0
  },
  {
   "metric": "SECURITY_POLICIES",
   "limit": 10.0,
   "usage": 0.0
  },
  {
   "metric": "SECURITY_POLICY_RULES",
   "limit": 1000.0,
   "usage": 0.0
  }
 ],
 "selfLink": "https://www.googleapis.com/compute/v1/projects/project1",
 "defaultServiceAccount": "1111111-compute@developer.gserviceaccount.com",
 "xpnProjectStatus": "UNSPECIFIED_XPN_PROJECT_STATUS"
}
"""

GET_PROJECT_NAME_RESPONSE = """
{
 "name": "project1"
}
"""

GET_QUOTA_RESPONSE = {u'usage': 0.0, u'metric': u'SNAPSHOTS', u'limit': 1000.0}

GET_FIREWALL_QUOTA_RESPONSE = {u'usage': 9.0, u'metric': u'FIREWALLS', u'limit': 100.0}

# Errors

API_NOT_ENABLED = """
{
 "error": {
  "errors": [
   {
    "domain": "usageLimits",
    "reason": "accessNotConfigured",
    "message": "Access Not Configured. Compute Engine API has not been used in project 1111111 before or it is disabled. Enable it by visiting https://console.developers.google.com/apis/api/compute.googleapis.com/overview?project=1111111 then retry. If you enabled this API recently, wait a few minutes for the action to propagate to our systems and retry.",
    "extendedHelp": "https://console.developers.google.com/apis/api/compute.googleapis.com/overview?project=1111111"
   }
  ],
  "code": 403,
  "message": "Access Not Configured. Compute Engine API has not been used in project 1111111 before or it is disabled. Enable it by visiting https://console.developers.google.com/apis/api/compute.googleapis.com/overview?project=1111111 then retry. If you enabled this API recently, wait a few minutes for the action to propagate to our systems and retry."
 }
}
"""

ACCESS_DENIED = """
{
 "error": {
  "errors": [
   {
    "domain": "global",
    "reason": "forbidden",
    "message": "Required 'compute.instances.list' permission for 'projects/project1'"
   }
  ],
  "code": 403,
  "message": "Required 'compute.instances.list' permission for 'projects/project1'"
 }
}
"""

NETWORKS_LIST_PAGE1 = """
{
 "kind": "compute#networkList",
 "id": "projects/project1/global/networks",
 "items": [
  {
   "kind": "compute#network",
   "id": "1234",
   "creationTimestamp": "2017-09-25T12:33:24.312-07:00",
   "name": "default1",
   "description": "Default network for the project",
   "selfLink": "https://www.googleapis.com/compute/v1/projects/project1/global/networks/default1",
   "autoCreateSubnetworks": true,
   "subnetworks": [
    "https://www.googleapis.com/compute/v1/projects/project1/regions/europe-west1/subnetworks/default1",
    "https://www.googleapis.com/compute/v1/projects/project1/regions/asia-east1/subnetworks/default1",
    "https://www.googleapis.com/compute/v1/projects/project1/regions/us-west1/subnetworks/default1",
    "https://www.googleapis.com/compute/v1/projects/project1/regions/asia-northeast1/subnetworks/default1",
    "https://www.googleapis.com/compute/v1/projects/project1/regions/us-central1/subnetworks/default1",
    "https://www.googleapis.com/compute/v1/projects/project1/regions/southamerica-east1/subnetworks/default1",
    "https://www.googleapis.com/compute/v1/projects/project1/regions/europe-west3/subnetworks/default1",
    "https://www.googleapis.com/compute/v1/projects/project1/regions/us-east1/subnetworks/default1",
    "https://www.googleapis.com/compute/v1/projects/project1/regions/us-east4/subnetworks/default1",
    "https://www.googleapis.com/compute/v1/projects/project1/regions/europe-west2/subnetworks/default1",
    "https://www.googleapis.com/compute/v1/projects/project1/regions/asia-southeast1/subnetworks/default1",
    "https://www.googleapis.com/compute/v1/projects/project1/regions/australia-southeast1/subnetworks/default1"
   ]
  }
 ],
 "nextPageToken": "12345",
 "selfLink": "https://www.googleapis.com/compute/v1/projects/project1/global/networks"
}
"""

NETWORKS_LIST_PAGE2 = """
{
 "kind": "compute#networkList",
 "id": "projects/project1/global/networks",
 "items": [
  {
   "kind": "compute#network",
   "id": "1234",
   "creationTimestamp": "2017-09-25T12:41:09.416-07:00",
   "name": "default2",
   "selfLink": "https://www.googleapis.com/compute/v1/projects/project1/global/networks/default2",
   "autoCreateSubnetworks": false,
   "subnetworks": [
    "https://www.googleapis.com/compute/v1/projects/project1/regions/us-central1/subnetworks/default2"
   ]
  }
 ],
 "selfLink": "https://www.googleapis.com/compute/v1/projects/project1/global/networks"
}
"""

LIST_NETWORKS_RESPONSES = [NETWORKS_LIST_PAGE1, NETWORKS_LIST_PAGE2]

EXPECTED_NETWORK_NAME = [u"default1", u"default2"]

SNAPSHOTS_LIST_PAGE1 = """
{
 "kind": "compute#snapshotList",
 "id": "projects/project1/global/snapshots",
 "items": [
  {
   "kind": "compute#snapshot",
   "id": "314159",
   "creationTimestamp": "2018-07-12T13:32:03.714-07:00",
   "name": "instance-1-1531427523",
   "description": "Daily snapshot of instance-1.",
   "status": "READY",
   "sourceDisk": "https://www.googleapis.com/compute/beta/projects/project1/zones/us-east1-b/disks/instance-1",
   "sourceDiskId": "7102445878994667099",
   "diskSizeGb": "10",
   "storageBytes": "536550912",
   "storageBytesStatus": "UP_TO_DATE",
   "licenses": [
    "https://www.googleapis.com/compute/beta/projects/debian-cloud/global/licenses/debian-9-stretch"
   ],
   "selfLink": "https://www.googleapis.com/compute/beta/projects/project1/global/snapshots/instance-1-1531427523",
   "labelFingerprint": "foofoo123",
   "licenseCodes": [
    "1000205"
   ],
   "storageLocations": [
    "us"
   ]
  },
  {
   "kind": "compute#snapshot",
   "id": "6021023",
   "creationTimestamp": "2018-07-12T13:32:03.912-07:00",
   "name": "instance-2-1531427523",
   "description": "Daily snapshot of instance-2.",
   "status": "READY",
   "sourceDisk": "https://www.googleapis.com/compute/beta/projects/project1/zones/us-east1-b/disks/instance-2",
   "sourceDiskId": "7102445878994667099",
   "diskSizeGb": "10",
   "storageBytes": "536550912",
   "storageBytesStatus": "UP_TO_DATE",
   "licenses": [
    "https://www.googleapis.com/compute/beta/projects/debian-cloud/global/licenses/debian-9-stretch"
   ],
   "selfLink": "https://www.googleapis.com/compute/beta/projects/project1/global/snapshots/instance-2-1531427523",
   "labelFingerprint": "foofoo456",
   "licenseCodes": [
    "1000205"
   ],
   "storageLocations": [
    "us"
   ]
  }
 ],
 "nextPageToken": "123",
 "selfLink": "https://www.googleapis.com/compute/beta/projects/project1/global/snapshots"
}
"""

SNAPSHOTS_LIST_PAGE2 = """
{
 "kind": "compute#snapshotList",
 "id": "projects/project1/global/snapshots",
 "items": [
  {
   "kind": "compute#snapshot",
   "id": "271828",
   "creationTimestamp": "2018-07-12T13:32:03.221-07:00",
   "name": "instance-3-1531427523",
   "description": "Daily snapshot of instance-3.",
   "status": "READY",
   "sourceDisk": "https://www.googleapis.com/compute/beta/projects/project1/zones/us-east1-b/disks/instance-3",
   "sourceDiskId": "7102445878994667099",
   "diskSizeGb": "10",
   "storageBytes": "536550912",
   "storageBytesStatus": "UP_TO_DATE",
   "licenses": [
    "https://www.googleapis.com/compute/beta/projects/debian-cloud/global/licenses/debian-9-stretch"
   ],
   "selfLink": "https://www.googleapis.com/compute/beta/projects/project1/global/snapshots/instance-3-1531427523",
   "labelFingerprint": "foofoo789",
   "licenseCodes": [
    "1000205"
   ],
   "storageLocations": [
    "us"
   ]
  }
 ],
 "selfLink": "https://www.googleapis.com/compute/beta/projects/project1/global/snapshots"
}
"""

LIST_SNAPSHOTS_RESPONSES = [SNAPSHOTS_LIST_PAGE1, SNAPSHOTS_LIST_PAGE2]

EXPECTED_SNAPSHOTS_LIST_NAMES = frozenset([
    "instance-1-1531427523",
    "instance-2-1531427523",
    "instance-3-1531427523"
])

SUBNETWORKS_AGGREGATED_LIST_PAGE1 = """
{
 "kind": "compute#subnetworkAggregatedList",
 "id": "projects/project1/aggregated/subnetworks",
 "items": {
  "regions/us-central1": {
   "subnetworks": [
    {
     "kind": "compute#subnetwork",
     "id": "1642482022657304820",
     "creationTimestamp": "2017-03-27T15:45:47.874-07:00",
     "name": "default1",
     "network": "https://www.googleapis.com/compute/v1/projects/project1/global/networks/default1",
     "ipCidrRange": "10.128.0.0/20",
     "gatewayAddress": "10.128.0.1",
     "region": "https://www.googleapis.com/compute/v1/projects/project1/regions/us-central1",
     "selfLink": "https://www.googleapis.com/compute/v1/projects/project1/regions/us-central1/subnetworks/default1",
     "privateIpGoogleAccess": false
    },
    {
     "kind": "compute#subnetwork",
     "id": "1642482022657304820",
     "creationTimestamp": "2017-05-22T13:03:40.235-07:00",
     "name": "default2",
     "network": "https://www.googleapis.com/compute/v1/projects/project1/global/networks/default2",
     "ipCidrRange": "192.168.0.0/20",
     "gatewayAddress": "192.168.0.1",
     "region": "https://www.googleapis.com/compute/v1/projects/project1/regions/us-central1",
     "selfLink": "https://www.googleapis.com/compute/v1/projects/project1/regions/us-central1/subnetworks/default2",
     "privateIpGoogleAccess": true
    }
   ]
  },
  "regions/europe-west1": {
   "subnetworks": [
    {
     "kind": "compute#subnetwork",
     "id": "1932934198276139252",
     "creationTimestamp": "2017-03-27T15:45:47.919-07:00",
     "name": "default1",
     "network": "https://www.googleapis.com/compute/v1/projects/project1/global/networks/default1",
     "ipCidrRange": "10.132.0.0/20",
     "gatewayAddress": "10.132.0.1",
     "region": "https://www.googleapis.com/compute/v1/projects/project1/regions/europe-west1",
     "selfLink": "https://www.googleapis.com/compute/v1/projects/project1/regions/europe-west1/subnetworks/default1",
     "privateIpGoogleAccess": false
    }
   ]
  },
  "regions/us-west1": {
   "subnetworks": [
    {
     "kind": "compute#subnetwork",
     "id": "5444425302580406516",
     "creationTimestamp": "2017-03-27T15:45:47.964-07:00",
     "name": "default1",
     "network": "https://www.googleapis.com/compute/v1/projects/project1/global/networks/default1",
     "ipCidrRange": "10.138.0.0/20",
     "gatewayAddress": "10.138.0.1",
     "region": "https://www.googleapis.com/compute/v1/projects/project1/regions/us-west1",
     "selfLink": "https://www.googleapis.com/compute/v1/projects/project1/regions/us-west1/subnetworks/default1",
     "privateIpGoogleAccess": false
    }
   ]
  },
  "regions/asia-east1": {
   "subnetworks": [
    {
     "kind": "compute#subnetwork",
     "id": "2025036026727377140",
     "creationTimestamp": "2017-03-27T15:45:47.987-07:00",
     "name": "default1",
     "network": "https://www.googleapis.com/compute/v1/projects/project1/global/networks/default1",
     "ipCidrRange": "10.140.0.0/20",
     "gatewayAddress": "10.140.0.1",
     "region": "https://www.googleapis.com/compute/v1/projects/project1/regions/asia-east1",
     "selfLink": "https://www.googleapis.com/compute/v1/projects/project1/regions/asia-east1/subnetworks/default1",
     "privateIpGoogleAccess": false
    }
   ]
  },
  "regions/us-east1": {
   "subnetworks": [
    {
     "kind": "compute#subnetwork",
     "id": "894326937629239539",
     "creationTimestamp": "2017-03-27T15:45:48.002-07:00",
     "name": "default1",
     "network": "https://www.googleapis.com/compute/v1/projects/project1/global/networks/default1",
     "ipCidrRange": "10.142.0.0/20",
     "gatewayAddress": "10.142.0.1",
     "region": "https://www.googleapis.com/compute/v1/projects/project1/regions/us-east1",
     "selfLink": "https://www.googleapis.com/compute/v1/projects/project1/regions/us-east1/subnetworks/default1",
     "privateIpGoogleAccess": false
    }
   ]
  },
  "regions/asia-northeast1": {
   "subnetworks": [
    {
     "kind": "compute#subnetwork",
     "id": "3985529683561425139",
     "creationTimestamp": "2017-03-27T15:45:48.018-07:00",
     "name": "default1",
     "network": "https://www.googleapis.com/compute/v1/projects/project1/global/networks/default1",
     "ipCidrRange": "10.146.0.0/20",
     "gatewayAddress": "10.146.0.1",
     "region": "https://www.googleapis.com/compute/v1/projects/project1/regions/asia-northeast1",
     "selfLink": "https://www.googleapis.com/compute/v1/projects/project1/regions/asia-northeast1/subnetworks/default1",
     "privateIpGoogleAccess": false
    }
   ]
  }
 },
 "nextPageToken": "12345",
 "selfLink": "https://www.googleapis.com/compute/v1/projects/project1/aggregated/subnetworks"
}
"""

SUBNETWORKS_AGGREGATED_LIST_PAGE2 = """
{
 "kind": "compute#subnetworkAggregatedList",
 "id": "projects/project1/aggregated/subnetworks",
 "items": {
  "regions/asia-southeast1": {
   "subnetworks": [
    {
     "kind": "compute#subnetwork",
     "id": "255819872288838938",
     "creationTimestamp": "2017-04-12T15:36:37.651-07:00",
     "name": "default1",
     "network": "https://www.googleapis.com/compute/v1/projects/project1/global/networks/default1",
     "ipCidrRange": "10.148.0.0/20",
     "gatewayAddress": "10.148.0.1",
     "region": "https://www.googleapis.com/compute/v1/projects/project1/regions/asia-southeast1",
     "selfLink": "https://www.googleapis.com/compute/v1/projects/project1/regions/asia-southeast1/subnetworks/default1",
     "privateIpGoogleAccess": false
    }
   ]
  },
  "regions/us-east4": {
   "subnetworks": [
    {
     "kind": "compute#subnetwork",
     "id": "4231032200360879984",
     "creationTimestamp": "2017-05-09T17:06:55.909-07:00",
     "name": "default1",
     "network": "https://www.googleapis.com/compute/v1/projects/project1/global/networks/default1",
     "ipCidrRange": "10.150.0.0/20",
     "gatewayAddress": "10.150.0.1",
     "region": "https://www.googleapis.com/compute/v1/projects/project1/regions/us-east4",
     "selfLink": "https://www.googleapis.com/compute/v1/projects/project1/regions/us-east4/subnetworks/default1",
     "privateIpGoogleAccess": false
    }
   ]
  },
  "regions/australia-southeast1": {
   "subnetworks": [
    {
     "kind": "compute#subnetwork",
     "id": "1254575737741270738",
     "creationTimestamp": "2017-06-20T19:55:57.803-07:00",
     "name": "default1",
     "network": "https://www.googleapis.com/compute/v1/projects/project1/global/networks/default1",
     "ipCidrRange": "10.152.0.0/20",
     "gatewayAddress": "10.152.0.1",
     "region": "https://www.googleapis.com/compute/v1/projects/project1/regions/australia-southeast1",
     "selfLink": "https://www.googleapis.com/compute/v1/projects/project1/regions/australia-southeast1/subnetworks/default1",
     "privateIpGoogleAccess": false
    }
   ]
  },
  "regions/europe-west2": {
   "subnetworks": [
    {
     "kind": "compute#subnetwork",
     "id": "1056942392408910390",
     "creationTimestamp": "2017-06-07T07:59:37.461-07:00",
     "name": "default1",
     "network": "https://www.googleapis.com/compute/v1/projects/project1/global/networks/default1",
     "ipCidrRange": "10.154.0.0/20",
     "gatewayAddress": "10.154.0.1",
     "region": "https://www.googleapis.com/compute/v1/projects/project1/regions/europe-west2",
     "selfLink": "https://www.googleapis.com/compute/v1/projects/project1/regions/europe-west2/subnetworks/default1",
     "privateIpGoogleAccess": false
    }
   ]
  },
  "regions/europe-west3": {
   "subnetworks": [
    {
     "kind": "compute#subnetwork",
     "id": "3562686695833601682",
     "creationTimestamp": "2017-08-02T04:33:17.768-07:00",
     "name": "default1",
     "network": "https://www.googleapis.com/compute/v1/projects/project1/global/networks/default1",
     "ipCidrRange": "10.156.0.0/20",
     "gatewayAddress": "10.156.0.1",
     "region": "https://www.googleapis.com/compute/v1/projects/project1/regions/europe-west3",
     "selfLink": "https://www.googleapis.com/compute/v1/projects/project1/regions/europe-west3/subnetworks/default1",
     "privateIpGoogleAccess": false
    }
   ]
  },
  "regions/southamerica-east1": {
   "subnetworks": [
    {
     "kind": "compute#subnetwork",
     "id": "2103435213001651085",
     "creationTimestamp": "2017-09-05T18:20:34.132-07:00",
     "name": "default1",
     "network": "https://www.googleapis.com/compute/v1/projects/project1/global/networks/default1",
     "ipCidrRange": "10.158.0.0/20",
     "gatewayAddress": "10.158.0.1",
     "region": "https://www.googleapis.com/compute/v1/projects/project1/regions/southamerica-east1",
     "selfLink": "https://www.googleapis.com/compute/v1/projects/project1/regions/southamerica-east1/subnetworks/default1",
     "privateIpGoogleAccess": false
    }
   ]
  }
 },
 "selfLink": "https://www.googleapis.com/compute/v1/projects/project1/aggregated/subnetworks"
}
"""

SUBNETWORKS_AGGREGATED_LIST = [SUBNETWORKS_AGGREGATED_LIST_PAGE1,
                               SUBNETWORKS_AGGREGATED_LIST_PAGE2]

BASE_URL = "https://www.googleapis.com/compute/v1/projects/project1"

EXPECTED_SUBNETWORKS_AGGREGATEDLIST_SELFLINKS = frozenset([
    "{}/regions/europe-west1/subnetworks/default1".format(BASE_URL),
    "{}/regions/asia-east1/subnetworks/default1".format(BASE_URL),
    "{}/regions/us-west1/subnetworks/default1".format(BASE_URL),
    "{}/regions/asia-northeast1/subnetworks/default1".format(BASE_URL),
    "{}/regions/us-central1/subnetworks/default1".format(BASE_URL),
    "{}/regions/southamerica-east1/subnetworks/default1".format(BASE_URL),
    "{}/regions/europe-west3/subnetworks/default1".format(BASE_URL),
    "{}/regions/us-east1/subnetworks/default1".format(BASE_URL),
    "{}/regions/us-east4/subnetworks/default1".format(BASE_URL),
    "{}/regions/europe-west2/subnetworks/default1".format(BASE_URL),
    "{}/regions/asia-southeast1/subnetworks/default1".format(BASE_URL),
    "{}/regions/australia-southeast1/subnetworks/default1".format(BASE_URL),
    "{}/regions/us-central1/subnetworks/default2".format(BASE_URL)
])

FAKE_SUBNETWORK_REGION = "us-central1"

SUBNETWORKS_LIST = """
{
 "kind": "compute#subnetworkList",
 "id": "projects/project1/regions/us-central1/subnetworks",
 "items": [
  {
   "kind": "compute#subnetwork",
   "id": "1642482022657304820",
   "creationTimestamp": "2017-03-27T15:45:47.874-07:00",
   "name": "default1",
   "network": "https://www.googleapis.com/compute/v1/projects/project1/global/networks/default1",
   "ipCidrRange": "10.128.0.0/20",
   "gatewayAddress": "10.128.0.1",
   "region": "https://www.googleapis.com/compute/v1/projects/project1/regions/us-central1",
   "selfLink": "https://www.googleapis.com/compute/v1/projects/project1/regions/us-central1/subnetworks/default1",
   "privateIpGoogleAccess": false
  },
  {
   "kind": "compute#subnetwork",
   "id": "1642482022657304820",
   "creationTimestamp": "2017-05-22T13:03:40.235-07:00",
   "name": "default2",
   "network": "https://www.googleapis.com/compute/v1/projects/project1/global/networks/default2",
   "ipCidrRange": "192.168.0.0/20",
   "gatewayAddress": "192.168.0.1",
   "region": "https://www.googleapis.com/compute/v1/projects/project1/regions/us-central1",
   "selfLink": "https://www.googleapis.com/compute/v1/projects/project1/regions/us-central1/subnetworks/default2",
   "privateIpGoogleAccess": true
  }
 ],
 "selfLink": "https://www.googleapis.com/compute/v1/projects/project1/regions/southamerica-east1/subnetworks"
}
"""

EXPECTED_SUBNETWORKS_LIST_SELFLINKS = frozenset([
    "{}/regions/us-central1/subnetworks/default1".format(BASE_URL),
    "{}/regions/us-central1/subnetworks/default2".format(BASE_URL)
])

GLOBAL_OPERATION_RESPONSE = """
{
 "kind": "compute#operation",
 "id": "1234",
 "name": "operation-1234",
 "operationType": "delete",
 "targetLink": "https://www.googleapis.com/compute/v1/projects/project1/global/firewalls/test-1234",
 "targetId": "123456",
 "status": "PENDING",
 "user": "mock_data@example.com",
 "progress": 0,
 "insertTime": "2017-08-08T10:37:55.413-07:00",
 "selfLink": "https://www.googleapis.com/compute/beta/projects/project1/global/operations/operation-1234"
}
"""

FAKE_OPERATION_ID = "operation-1234"

# Parameters: verb, resource_path
PENDING_OPERATION_TEMPLATE = """
{{
 "kind": "compute#operation",
 "id": "1234",
 "name": "operation-1234",
 "operationType": "{verb}",
 "targetLink": "https://www.googleapis.com/compute/v1/projects/{resource_path}",
 "targetId": "123456",
 "status": "PENDING",
 "user": "mock_data@example.com",
 "progress": 0,
 "insertTime": "2018-08-02T06:49:34.713-07:00",
 "selfLink": "https://www.googleapis.com/compute/v1/projects/project1/global/operations/operation-1234"
}}
"""

# Parameters: verb, resource_path
FINISHED_OPERATION_TEMPLATE = """
{{
 "kind": "compute#operation",
 "id": "1234",
 "name": "operation-1234",
 "operationType": "{verb}",
 "targetLink": "https://www.googleapis.com/compute/v1/projects/{resource_path}",
 "targetId": "123456",
 "status": "DONE",
 "user": "mock_data@example.com",
 "progress": 100,
 "insertTime": "2018-08-02T06:49:34.713-07:00",
 "startTime": "2018-08-02T06:49:35.560-07:00",
 "endTime": "2018-08-02T06:49:42.937-07:00",
 "selfLink": "https://www.googleapis.com/compute/v1/projects/project1/global/operations/operation-1234"
}}
"""

FAKE_FIREWALL_RULE = {
    "kind": "compute#firewall",
    "id": "12345",
    "creationTimestamp": "2017-05-04T16:23:00.568-07:00",
    "network": ("https://www.googleapis.com/compute/beta/projects/project1"
                "/global/networks/default1"),
    "priority": 1000,
    "sourceRanges": ["0.0.0.0/0"],
    "description": "Allow SSH from anywhere",
    "allowed": [
        {
            "IPProtocol": "tcp",
            "ports": ["22"]
        }
    ],
    "name": "fake-firewall",
    "direction": "INGRESS",
    "selfLink": ("https://www.googleapis.com/compute/beta/projects/project1"
                 "/global/firewalls/fake-firewall")
}
