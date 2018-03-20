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

"""Test data for Google Kubernetes Engine GCP api responses."""

FAKE_PROJECT_ID = "project1"
FAKE_ZONE = "us-central1-a"
FAKE_LOCATION = "europe-west1"
FAKE_BAD_ZONE = "bad-zone"

FAKE_GET_SERVERCONFIG_RESPONSE = """
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

FAKE_GET_CLUSTERS_RESPONSE = """
{
  "clusters": [
    {
      "name": "cluster-1",
      "nodeConfig": {
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
      },
      "masterAuth": {
        "username": "user",
        "password": "pass",
        "clusterCaCertificate": "AB",
        "clientCertificate": "AB",
        "clientKey": "AB"
      },
      "loggingService": "logging.googleapis.com",
      "monitoringService": "none",
      "network": "default",
      "clusterIpv4Cidr": "10.8.0.0/14",
      "addonsConfig": {
        "httpLoadBalancing": {},
        "kubernetesDashboard": {},
        "networkPolicyConfig": {
          "disabled": true
        }
      },
      "subnetwork": "default",
      "nodePools": [
        {
          "name": "default-pool",
          "config": {
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
          },
          "initialNodeCount": 3,
          "autoscaling": {},
          "management": {
            "autoUpgrade": true
          },
          "selfLink": "https://container.googleapis.com/v1/projects/project1/zones/us-central1-a/clusters/cluster-1/nodePools/default-pool",
          "version": "1.7.11-gke.1",
          "instanceGroupUrls": [
            "https://www.googleapis.com/compute/v1/projects/project1/zones/us-central1-a/instanceGroupManagers/gke-cluster-1-default-pool-12345678-grp"
          ],
          "status": "RUNNING"
        }
      ],
      "locations": [
        "us-central1-a"
      ],
      "labelFingerprint": "abcdef12",
      "legacyAbac": {},
      "networkPolicy": {
        "provider": "CALICO"
      },
      "ipAllocationPolicy": {},
      "masterAuthorizedNetworksConfig": {},
      "selfLink": "https://container.googleapis.com/v1/projects/project1/zones/us-central1-a/clusters/cluster-1",
      "zone": "us-central1-a",
      "endpoint": "10.0.0.1",
      "initialClusterVersion": "1.7.6-gke.1",
      "currentMasterVersion": "1.7.11-gke.1",
      "currentNodeVersion": "1.7.11-gke.1",
      "createTime": "2017-10-24T19:36:21+00:00",
      "status": "RUNNING",
      "nodeIpv4CidrSize": 24,
      "servicesIpv4Cidr": "10.11.240.0/20",
      "instanceGroupUrls": [
        "https://www.googleapis.com/compute/v1/projects/project1/zones/us-central1-a/instanceGroupManagers/gke-cluster-1-default-pool-12345678-grp"
      ],
      "currentNodeCount": 3
    }
  ]
}
"""

EXPECTED_CLUSTER_NAMES = ["cluster-1"]

INVALID_ARGUMENT_400 = """
{
  "error": {
    "code": 400,
    "message": "zone \"bad-zone\" does not exist.",
    "status": "INVALID_ARGUMENT"
  }
}
"""
