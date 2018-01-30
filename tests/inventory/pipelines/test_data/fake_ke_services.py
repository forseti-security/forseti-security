# Copyright 2017 The Forseti Security Authors. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the 'License');
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an 'AS IS' BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Fake KE services data."""


FAKE_SERVER_CONFIG = {  
       'validImageTypes':[
          'UBUNTU',
          'COS'
       ],
       'defaultImageType': 'COS',
       'validNodeVersions':[  
          '1.8.6-gke.0',
          '1.8.5-gke.0',
          '1.8.4-gke.1',
          '1.8.3-gke.0',
          '1.8.2-gke.0',
          '1.8.1-gke.1',
          '1.7.12-gke.0',
          '1.7.11-gke.1',
          '1.7.11',
          '1.7.10-gke.0',
          '1.7.8-gke.0',
          '1.6.13-gke.1',
          '1.6.11-gke.0',
          '1.5.7'
       ],
       'validMasterVersions':[  
          '1.8.6-gke.0',
          '1.8.5-gke.0',
          '1.7.12-gke.0',
          '1.7.11-gke.1'
       ],
       'defaultClusterVersion': '1.7.11-gke.1'
    }


# This is different from the api test data in the the server_config is included
# in the cluster data.
FAKE_KE_SERVICES_MAP = {
    'project1': [{
    'addonsConfig':{  
       'networkPolicyConfig':{  
          'disabled': True
       }
    },
    'clusterIpv4Cidr': '10.60.0.0/14',
    'createTime': '2016-11-12T17:57:49+00:00',
    'currentMasterVersion': '1.6.13-gke.1',
    'currentNodeCount':2,
    'currentNodeVersion': '1.4.5',
    'endpoint': '111.111.111.11',
    'initialClusterVersion': '1.4.5',
    'instanceGroupUrls':[  
       'https://www.googleapis.com/compute/v1/projects/fooproject/zones/us-central1-b/instanceGroupManagers/fooinstancegroup--default-pool-1388e059-grp'
    ],
    'legacyAbac':{  
       'enabled':True
    },
    'locations':[  
       'us-central1-b'
    ],
    'loggingService': 'logging.googleapis.com',
    'masterAuth':{  
       'password': 'pass',
       'username': 'user',
       'clientKey': 'AB',
       'clientCertificate': 'AB',
       'clusterCaCertificate': 'AB'
    },
    'monitoringService': 'none',
    'name': 'foocluster-central',
    'network': 'default',
    'nodeConfig':{  
       'imageType': 'COS',
       'diskSizeGb':100,
       'machineType': 'n1-standard-1',
       'oauthScopes':[  
          'https://www.googleapis.com/auth/compute',
          'https://www.googleapis.com/auth/devstorage.read_only',
          'https://www.googleapis.com/auth/logging.write',
          'https://www.googleapis.com/auth/servicecontrol',
          'https://www.googleapis.com/auth/service.management.readonly',
          'https://www.googleapis.com/auth/trace.append'
       ],
       'serviceAccount': 'default'
    },
    'nodeIpv4CidrSize':24,
    'nodePools':[  
       {  
          'name': 'default-pool',
          'config':{  
             'imageType': 'COS',
             'diskSizeGb':100,
             'machineType': 'n1-standard-1',
             'oauthScopes':[  
                'https://www.googleapis.com/auth/compute',
                'https://www.googleapis.com/auth/devstorage.read_only',
                'https://www.googleapis.com/auth/logging.write',
                'https://www.googleapis.com/auth/servicecontrol',
                'https://www.googleapis.com/auth/service.management.readonly',
                'https://www.googleapis.com/auth/trace.append'
             ],
             'serviceAccount': 'default'
          },
          'status': 'RUNNING',
          'version': '1.4.5',
          'selfLink': 'https://container.googleapis.com/v1/projects/fooproject/zones/us-central1-b/clusters/foocluster-central/nodePools/default-pool',
          'management':{  

          },
          'autoscaling':{  

          },
          'initialNodeCount':1,
          'instanceGroupUrls':[  
             'https://www.googleapis.com/compute/v1/projects/fooproject/zones/us-central1-b/instanceGroupManagers/fooinstancegroup--default-pool-1388e059-grp'
          ]
       }
    ],
    'selfLink': 'https://container.googleapis.com/v1/projects/fooproject/zones/us-central1-b/clusters/foocluster-central',
    'serverConfig': FAKE_SERVER_CONFIG,
    'servicesIpv4Cidr': '10.63.240.0/20',
    'status': 'RUNNING',
    'subnetwork': 'default',
    'zone': 'us-central1-b',
    }]
}


EXPECTED_LOADABLE_KE_SERVICES = [
    {'addons_config': '{"networkPolicyConfig": {"disabled": true}}',
     'cluster_ipv4_cidr': '10.60.0.0/14',
     'create_time': '2016-11-12T17:57:49+00:00',
     'current_master_version': '1.6.13-gke.1',
     'current_node_count': 2,
     'current_node_version': '1.4.5',
     'endpoint': '111.111.111.11',
     'initial_cluster_version': '1.4.5',
     'instance_group_urls': ['https://www.googleapis.com/compute/v1/projects/fooproject/zones/us-central1-b/instanceGroupManagers/fooinstancegroup--default-pool-1388e059-grp'],
     'legacy_abac': '{"enabled": true}',
     'locations': ['us-central1-b'],
     'logging_service': 'logging.googleapis.com',
     'monitoring_service': 'none',
     'name': 'foocluster-central',
     'network': 'default',
     'node_config': '{"diskSizeGb": 100, "machineType": "n1-standard-1", "oauthScopes": ["https://www.googleapis.com/auth/compute", "https://www.googleapis.com/auth/devstorage.read_only", "https://www.googleapis.com/auth/logging.write", "https://www.googleapis.com/auth/servicecontrol", "https://www.googleapis.com/auth/service.management.readonly", "https://www.googleapis.com/auth/trace.append"], "imageType": "COS", "serviceAccount": "default"}',
     'node_ipv4_cidr_size': 24,
     'node_pools': '[{"status": "RUNNING", "version": "1.4.5", "name": "default-pool", "instanceGroupUrls": ["https://www.googleapis.com/compute/v1/projects/fooproject/zones/us-central1-b/instanceGroupManagers/fooinstancegroup--default-pool-1388e059-grp"], "management": {}, "autoscaling": {}, "config": {"diskSizeGb": 100, "machineType": "n1-standard-1", "oauthScopes": ["https://www.googleapis.com/auth/compute", "https://www.googleapis.com/auth/devstorage.read_only", "https://www.googleapis.com/auth/logging.write", "https://www.googleapis.com/auth/servicecontrol", "https://www.googleapis.com/auth/service.management.readonly", "https://www.googleapis.com/auth/trace.append"], "imageType": "COS", "serviceAccount": "default"}, "selfLink": "https://container.googleapis.com/v1/projects/fooproject/zones/us-central1-b/clusters/foocluster-central/nodePools/default-pool", "initialNodeCount": 1}]',
     'project_id': 'project1',
     'raw_cluster': '{"nodeIpv4CidrSize": 24, "addonsConfig": {"networkPolicyConfig": {"disabled": true}}, "locations": ["us-central1-b"], "legacyAbac": {"enabled": true}, "network": "default", "loggingService": "logging.googleapis.com", "instanceGroupUrls": ["https://www.googleapis.com/compute/v1/projects/fooproject/zones/us-central1-b/instanceGroupManagers/fooinstancegroup--default-pool-1388e059-grp"], "zone": "us-central1-b", "servicesIpv4Cidr": "10.63.240.0/20", "status": "RUNNING", "currentNodeVersion": "1.4.5", "currentMasterVersion": "1.6.13-gke.1", "masterAuth": "<not saved in forseti inventory>", "nodePools": [{"status": "RUNNING", "version": "1.4.5", "name": "default-pool", "instanceGroupUrls": ["https://www.googleapis.com/compute/v1/projects/fooproject/zones/us-central1-b/instanceGroupManagers/fooinstancegroup--default-pool-1388e059-grp"], "management": {}, "autoscaling": {}, "config": {"diskSizeGb": 100, "machineType": "n1-standard-1", "oauthScopes": ["https://www.googleapis.com/auth/compute", "https://www.googleapis.com/auth/devstorage.read_only", "https://www.googleapis.com/auth/logging.write", "https://www.googleapis.com/auth/servicecontrol", "https://www.googleapis.com/auth/service.management.readonly", "https://www.googleapis.com/auth/trace.append"], "imageType": "COS", "serviceAccount": "default"}, "selfLink": "https://container.googleapis.com/v1/projects/fooproject/zones/us-central1-b/clusters/foocluster-central/nodePools/default-pool", "initialNodeCount": 1}], "monitoringService": "none", "createTime": "2016-11-12T17:57:49+00:00", "endpoint": "111.111.111.11", "currentNodeCount": 2, "name": "foocluster-central", "serverConfig": {"validNodeVersions": ["1.8.6-gke.0", "1.8.5-gke.0", "1.8.4-gke.1", "1.8.3-gke.0", "1.8.2-gke.0", "1.8.1-gke.1", "1.7.12-gke.0", "1.7.11-gke.1", "1.7.11", "1.7.10-gke.0", "1.7.8-gke.0", "1.6.13-gke.1", "1.6.11-gke.0", "1.5.7"], "defaultClusterVersion": "1.7.11-gke.1", "validImageTypes": ["UBUNTU", "COS"], "validMasterVersions": ["1.8.6-gke.0", "1.8.5-gke.0", "1.7.12-gke.0", "1.7.11-gke.1"], "defaultImageType": "COS"}, "initialClusterVersion": "1.4.5", "nodeConfig": {"diskSizeGb": 100, "machineType": "n1-standard-1", "oauthScopes": ["https://www.googleapis.com/auth/compute", "https://www.googleapis.com/auth/devstorage.read_only", "https://www.googleapis.com/auth/logging.write", "https://www.googleapis.com/auth/servicecontrol", "https://www.googleapis.com/auth/service.management.readonly", "https://www.googleapis.com/auth/trace.append"], "imageType": "COS", "serviceAccount": "default"}, "clusterIpv4Cidr": "10.60.0.0/14", "subnetwork": "default", "selfLink": "https://container.googleapis.com/v1/projects/fooproject/zones/us-central1-b/clusters/foocluster-central"}',
     'self_link': 'https://container.googleapis.com/v1/projects/fooproject/zones/us-central1-b/clusters/foocluster-central',
     'server_config': '{"validNodeVersions": ["1.8.6-gke.0", "1.8.5-gke.0", "1.8.4-gke.1", "1.8.3-gke.0", "1.8.2-gke.0", "1.8.1-gke.1", "1.7.12-gke.0", "1.7.11-gke.1", "1.7.11", "1.7.10-gke.0", "1.7.8-gke.0", "1.6.13-gke.1", "1.6.11-gke.0", "1.5.7"], "defaultClusterVersion": "1.7.11-gke.1", "validImageTypes": ["UBUNTU", "COS"], "validMasterVersions": ["1.8.6-gke.0", "1.8.5-gke.0", "1.7.12-gke.0", "1.7.11-gke.1"], "defaultImageType": "COS"}',
     'services_ipv4_cidr': '10.63.240.0/20',
     'status': 'RUNNING',
     'subnetwork': 'default',
     'zone': 'us-central1-b'}
]
