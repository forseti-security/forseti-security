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
"""Fake instance data."""

# pylint: disable=line-too-long
INSTANCE_DATA = [{
    'can_ip_forware': 'boolean',
    'cpu_platform': 'Intel Ivy Bridge',
    'creation_timestamp': '1000-00-00T00:00:00.000-00:00',
    'description': 'description-1',
    'disks': [{'boot': 'true', 'kind': 'compute#attachedDisk', 'mode': 'READ_WRITE', 'type': 'PERSISTENT', 'index': 0, 'source': 'https://www.googleapis.com/compute/v1/projects/projects-1/zones/datacenter/disks/something', 'interface': 'SCSI', 'autoDelete': 'true', 'deviceName': 'something-2-1111'}],
    'machine_type': 'https://www.googleapis.com/compute/v1/projects/project-1/zones/datacenter/machineTypes/n1-standard-16',
    'metadata': {'kind': 'computemetadata', 'items': [{'key': 'eventName', 'value': 'RequestTime'}, {'key': 'serviceName', 'value': 'none'}, {'key': 'subscriptionName', 'value': 'request'}, {'key': 'instance-template', 'value': 'projects/9999/global/instanceTemplates/something'}, {'key': 'created-by', 'value': 'projects/1111/regions/another-datacenter/groups/request'}], 'fingerprint': 'YYYY'},
    'name': 'name-0',
    'network_interfaces': [{'kind': 'computenetworkInterface', 'name': 'nic0', 'network': 'https://www.googleapis.com/compute/v1/projects/project-1/global/networks/network-1', 'networkIP': '000.000.000.000', 'subnetwork': 'https://www.googleapis.com/compute/v1/projects/project-1/regions/datacenter/subnetworks/subnetwork-1', 'accessConfigs': [{'kind': 'computeaccessConfig', 'name': 'External NAT', 'type': 'ONE_TO_ONE_NAT', 'natIP': '000.000.000.001'}]}],
    'project_id': 'project_id-1',
    'resource_id': 'resource_id-2',
    'scheduling': {'preemptible': 'false', 'automaticRestart': 'true', 'onHostMaintenance': 'MIGRATE'},
    'service_accounts': [{'email': 'none@developer.gserviceaccount.com', 'scopes': ['https://www.googleapis.com/auth/somewhere']}],
    'status': 'status-1',
    'status_message': 'status_message-1',
    'tags': {'items': ['one', 'two', 'three'], 'fingerprint': 'wwww'},
    'zone': 'zone-1'
},
{
    'can_ip_forware': 'boolean',
    'cpu_platform': 'Intel Ivy Bridge',
    'creation_timestamp': '2000-00-00T00:00:00.000-00:00',
    'description': '',
    'disks': [{'boot': 'true', 'kind': 'compute#attachedDisk', 'mode': 'READ_WRITE', 'type': 'PERSISTENT', 'index': 0, 'source': 'https://www.googleapis.com/compute/v1/projects/projects-1/zones/datacenter/disks/something', 'interface': 'SCSI', 'autoDelete': 'true', 'deviceName': 'something-2-1111'}],
    'machine_type': 'https://www.googleapis.com/compute/v1/projects/project-1/zones/datacenter/machineTypes/n1-standard-16',
    'metadata': {'kind': 'computemetadata', 'items': [{'key': 'eventName', 'value': 'RequestTime'}, {'key': 'serviceName', 'value': 'none'}, {'key': 'subscriptionName', 'value': 'request'}, {'key': 'instance-template', 'value': 'projects/9999/global/instanceTemplates/something'}, {'key': 'created-by', 'value': 'projects/1111/regions/another-datacenter/groups/request'}], 'fingerprint': 'YYYY'},
    'name': 'name-1',
    'network_interfaces': [{'kind': 'computenetworkInterface', 'name': 'nic0', 'network': 'https://www.googleapis.com/compute/v1/projects/project-2/global/networks/network-2', 'networkIP': '0.0.0.0', 'subnetwork': 'https://www.googleapis.com/compute/v1/projects/xpn-master/regions/datacenter/subnetworks/subnetworks-2', 'accessConfigs': [{'kind': 'compute#accessConfig', 'name': 'External NAT', 'type': 'ONE_TO_ONE_NAT', 'natIP': '0.0.0.2'}]}, {'kind': 'compute#networkInterface', 'name': 'nic0', 'network': 'https://www.googleapis.com/compute/v1/projects/project-2/global/networks/network-2-2', 'networkIP': '0.0.0.0', 'subnetwork': 'https://www.googleapis.com/compute/v1/projects/project-2/regions/datacenter/subnetworks/subnetwork-2'}],
    'project_id': '3333',
    'resource_id': '5555',
    'scheduling': {'preemptible': 'false', 'automaticRestart': 'true', 'onHostMaintenance': 'MIGRATE'},
    'service_accounts': [{'email': 'none@developer.gserviceaccount.com', 'scopes': ['https://www.googleapis.com/auth/somewhere']}],
    'status': 'RUNNING',
    'status_message': '',
    'tags': {'items': ['one', 'two', 'three'], 'fingerprint': 'xxxx'},
    'zone': 'https://www.googleapis.com/compute/v1/projects/project-1/zones/datacenter'
},
{
    'can_ip_forware': 'boolean',
    'cpu_platform': 'Intel Ivy Bridge',
    'creation_timestamp': '1000-00-00T00:00:00.000-00:00',
    'description': '',
    'disks': [{'boot': 'true', 'kind': 'computeattachedDisk', 'mode': 'READ_WRITE', 'type': 'PERSISTENT', 'index': 0, 'source': 'https://www.googleapis.com/compute/v1/projects/project-1/zones/datacenter/disks/something', 'interface': 'SCSI', 'autoDelete': 'true', 'deviceName': 'something-9999'}],
    'machine_type': 'https://www.googleapis.com/compute/v1/projects/project-1/zones/datacenter/machineTypes/n1-standard-16',
    'metadata': {'kind': 'compute#metadata', 'items': [{'key': 'eventName', 'value': 'RequestTime'}, {'key': 'serviceName', 'value': 'request-1'}, {'key': 'subscriptionName', 'value': 'project.request'}, {'key': 'qqqq', 'value': 'projects/project-1/global/global-1/request'}, {'key': 'created-by', 'value': 'projects/0000/regions/another-datacenter/groups/request'}], 'fingerprint': 'ZZZZZ'},
    'name': 'name-0',
    'network_interfaces': [{'kind': 'compute#networkInterface', 'name': 'nic0', 'network': 'https://www.googleapis.com/compute/v1/projects/project-3/global/networks/network-3', 'networkIP': '000.000.000.000', 'accessConfigs': [{'kind': 'compute#accessConfig', 'name': 'External NAT', 'type': 'ONE_TO_ONE_NAT', 'natIP': '000.000.000.001'}]}],
    'project_id': '2222',
    'resource_id': '4444',
    'scheduling': {'preemptible': 'false', 'automaticRestart': 'true', 'onHostMaintenance': 'MIGRATE'},
    'service_accounts': [{'email': 'none@developer.gserviceaccount.com', 'scopes': ['https://www.googleapis.com/auth/somewhere']}],
    'status': 'RUNNING',
    'status_message': '',
    'tags': {'items': ['one', 'two', 'three'], 'fingerprint': 'wwww'},
    'zone': 'https://www.googleapis.com/compute/v1/projects/project-1/zones/datacenter'
},
{
    'can_ip_forware': 'boolean',
    'cpu_platform': 'Intel Ivy Bridge',
    'creation_timestamp': '1000-00-00T00:00:00.000-00:00',
    'description': '',
    'disks': [{'boot': 'true', 'kind': 'compute#attachedDisk', 'mode': 'READ_WRITE', 'type': 'PERSISTENT', 'index': 0, 'source': 'https://www.googleapis.com/compute/v1/projects/project-1/zones/datacenter/disks/something', 'interface': 'SCSI', 'autoDelete': 'true', 'deviceName': 'something-9999'}],
    'machine_type': 'https://www.googleapis.com/compute/v1/projects/project-1/zones/datacenter/machineTypes/n1-standard-16',
    'metadata': {'kind': 'compute#metadata', 'items': [{'key': 'eventName', 'value': 'RequestTime'}, {'key': 'serviceName', 'value': 'request-1'}, {'key': 'subscriptionName', 'value': 'project.request'}, {'key': 'qqqq', 'value': 'projects/project-1/global/global-1/request'}, {'key': 'created-by', 'value': 'projects/0000/regions/another-datacenter/groups/request'}], 'fingerprint': 'ZZZZZ'},
    'name': 'name-0',
    'network_interfaces': [{'kind': 'compute#networkInterface', 'name': 'nic0', 'network': 'https://www.googleapis.com/compute/v1/projects/project-4/global/networks/network-4', 'networkIP': '000.000.000.000', 'accessConfigs': [{'kind': 'compute#accessConfig', 'name': 'External NAT', 'type': 'ONE_TO_ONE_NAT', 'natIP': '000.000.000.001'}]}],
    'project_id': '2222',
    'resource_id': '4444',
    'scheduling': {'preemptible': 'false', 'automaticRestart': 'true', 'onHostMaintenance': 'MIGRATE'},
    'service_accounts': [{'email': 'none@developer.gserviceaccount.com', 'scopes': ['https://www.googleapis.com/auth/somewhere']}],
    'status': 'RUNNING',
    'status_message': '',
    'tags': {'items': ['one', 'two', 'three'], 'fingerprint': 'wwww'},
    'zone': 'https://www.googleapis.com/compute/v1/projects/project-1/zones/datacenter'
}]


