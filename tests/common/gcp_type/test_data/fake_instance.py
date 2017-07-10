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

from copy import deepcopy

"""Fake cloudsql data."""

FAKE_INSTANCE_RESPONSE_1 = {
    'can_ip_forware': 'boolean',
    'cpu_platform': 'Intel Ivy Bridge',
    'creation_timestamp:2017-03-09T06': '04:53.791-08:00',
    'description': '',
    'disks': '[{"boot": true, "kind": "compute#attachedDisk", "mode": "READ_WRITE", "type": "PERSISTENT", "index": 0, "source": "https://www.googleapis.com/compute/v1/projects/spotify-facebook-system/zones/asia-east1-c/disks/gae2-facebook-a-k9br", "interface": "SCSI", "autoDelete": true, "deviceName": "cpm-gae2-facebook-a-20170130131417"}]',
    'machine_type': 'https://www.googleapis.com/compute/v1/projects/spotify-facebook-system/zones/asia-east1-c/machineTypes/n1-standard-16',
    'metadata': '{"kind": "compute#metadata", "items": [{"key": "eventName", "value": "RequestTime"}, {"key": "serviceName", "value": "ap"}, {"key": "subscriptionName", "value": "gabopc.com.spotify.logrecord.ap.requesttime"}, {"key": "instance-template", "value": "projects/357710781253/global/instanceTemplates/gabo-regional-consumer-ap-requesttime-da91a7f0"}, {"key": "created-by", "value": "projects/357710781253/regions/europe-west1/instanceGroupManagers/gabo-regional-consumer-ap-requesttime"}], "fingerprint": "2HZI5ZYFRZw="}',
    'name': 'gae2-facebook-a-k9br',
    'network_interfaces': '[{"kind": "compute#networkInterface", "name": "nic0", "network": "https://www.googleapis.com/compute/v1/projects/xpn-master/global/networks/xpn-network", "networkIP": "10.175.3.132", "subnetwork": "https://www.googleapis.com/compute/v1/projects/xpn-master/regions/asia-east1/subnetworks/xpn-ase1", "accessConfigs": [{"kind": "compute#accessConfig", "name": "External NAT", "type": "ONE_TO_ONE_NAT", "natIP": "104.199.244.119"}]}]',
    'project_id': 'spotify-facebook-system',
    'resource_id': '1128758315376618',
    'scheduling': '{"preemptible": false, "automaticRestart": true, "onHostMaintenance": "MIGRATE"}',
    'service_accounts': '[{"email": "775716291138-compute@developer.gserviceaccount.com", "scopes": ["https://www.googleapis.com/auth/cloud-platform"]}]',
    'status': 'RUNNING',
    'status_message': '',
    'tags': '{"items": ["pod-gae2", "pool-a", "role-facebook"], "fingerprint": "42WmSpB8rSM="}',
    'zone': 'https://www.googleapis.com/compute/v1/projects/spotify-facebook-system/zones/asia-east1-c'
}

FAKE_INSTANCE_RESPONSE_2 = {
    'can_ip_forware': 'boolean',
    'cpu_platform': 'Intel Ivy Bridge',
    'creation_timestamp': '2017-03-09T06:04:53.791-08:00',
    'description': '',
    'disks': '[{"boot": true, "kind": "compute#attachedDisk", "mode": "READ_WRITE", "type": "PERSISTENT", "index": 0, "source": "https://www.googleapis.com/compute/v1/projects/spotify-facebook-system/zones/asia-east1-c/disks/gae2-facebook-a-k9br", "interface": "SCSI", "autoDelete": true, "deviceName": "cpm-gae2-facebook-a-20170130131417"}]',
    'machine_type': 'https://www.googleapis.com/compute/v1/projects/spotify-facebook-system/zones/asia-east1-c/machineTypes/n1-standard-16',
    'metadata': '{"kind": "compute#metadata", "items": [{"key": "eventName", "value": "RequestTime"}, {"key": "serviceName", "value": "ap"}, {"key": "subscriptionName", "value": "gabopc.com.spotify.logrecord.ap.requesttime"}, {"key": "instance-template", "value": "projects/357710781253/global/instanceTemplates/gabo-regional-consumer-ap-requesttime-da91a7f0"}, {"key": "created-by", "value": "projects/357710781253/regions/europe-west1/instanceGroupManagers/gabo-regional-consumer-ap-requesttime"}], "fingerprint": "2HZI5ZYFRZw="}',
    'name': 'gae2-facebook-a-k9br',
    'network_interfaces': '[{"kind": "compute#networkInterface", "name": "nic0", "network": "https://www.googleapis.com/compute/v1/projects/xpn-master/global/networks/xpn-network", "networkIP": "10.175.3.132", "subnetwork": "https://www.googleapis.com/compute/v1/projects/xpn-master/regions/asia-east1/subnetworks/xpn-ase1", "accessConfigs": [{"kind": "compute#accessConfig", "name": "External NAT", "type": "ONE_TO_ONE_NAT", "natIP": "104.199.244.119"}]}, {"kind": "compute#networkInterface", "name": "nic0", "network": "https://www.googleapis.com/compute/v1/projects/xpn-master/global/networks/xpn-network", "networkIP": "10.175.3.132", "subnetwork": "https://www.googleapis.com/compute/v1/projects/xpn-master/regions/asia-east1/subnetworks/xpn-ase1", "accessConfigs": [{"kind": "compute#accessConfig", "name": "External NAT", "type": "ONE_TO_ONE_NAT", "natIP": "104.199.244.119"}]}]',
    'project_id': 'spotify-facebook-system',
    'resource_id': '1128758315376618',
    'scheduling': '{"preemptible": false, "automaticRestart": true, "onHostMaintenance": "MIGRATE"}',
    'service_accounts': '[{"email": "775716291138-compute@developer.gserviceaccount.com", "scopes": ["https://www.googleapis.com/auth/cloud-platform"]}]',
    'status': 'RUNNING',
    'status_message': '',
    'tags': '{"items": ["pod-gae2", "pool-a", "role-facebook"], "fingerprint": "42WmSpB8rSM="}',
    'zone': 'https://www.googleapis.com/compute/v1/projects/spotify-facebook-system/zones/asia-east1-c'
}

EXPECTED_FAKE_INSTANCE_FROM_API_1 = [deepcopy(FAKE_INSTANCE_RESPONSE_1)]
EXPECTED_FAKE_INSTANCE_FROM_API_2 = [deepcopy(FAKE_INSTANCE_RESPONSE_2)]
