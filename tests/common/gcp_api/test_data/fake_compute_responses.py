# Copyright 2017 Google Inc.
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
   "network": "https://www.googleapis.com/compute/beta/projects/project1/global/networks/default",
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
   "network": "https://www.googleapis.com/compute/beta/projects/project1/global/networks/default",
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
   "network": "https://www.googleapis.com/compute/beta/projects/project1/global/networks/default",
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
   "network": "https://www.googleapis.com/compute/beta/projects/project1/global/networks/default",
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
       "network": "https://www.googleapis.com/compute/v1/projects/project1/global/networks/default",
       "subnetwork": "https://www.googleapis.com/compute/v1/projects/project1/regions/us-central1/subnetworks/default",
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
     "network": "https://www.googleapis.com/compute/v1/projects/project1/global/networks/default",
     "subnetwork": "https://www.googleapis.com/compute/v1/projects/project1/regions/us-central1/subnetworks/default",
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
FAKE_INSTANCE_GROUP_REGION = 'us-central1'

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
     "network": "https://www.googleapis.com/compute/v1/projects/project1/global/networks/default",
     "fingerprint": "42WmSpB8rSM=",
     "selfLink": "https://www.googleapis.com/compute/v1/projects/project1/regions/us-central1/instanceGroups/iap-ig-region",
     "size": 3,
     "region": "https://www.googleapis.com/compute/v1/projects/project1/regions/us-central1",
     "subnetwork": "https://www.googleapis.com/compute/v1/projects/project1/regions/us-central1/subnetworks/default"
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
     "network": "https://www.googleapis.com/compute/v1/projects/project1/global/networks/default",
     "fingerprint": "42WmSpB8rSM=",
     "zone": "https://www.googleapis.com/compute/v1/projects/project1/zones/us-central1-c",
     "selfLink": "https://www.googleapis.com/compute/v1/projects/project1/zones/us-central1-c/instanceGroups/iap-ig",
     "size": 1,
     "subnetwork": "https://www.googleapis.com/compute/v1/projects/project1/regions/us-central1/subnetworks/default"
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
      "network": "https://www.googleapis.com/compute/v1/projects/project1/global/networks/default",
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
