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

"""Fake cloudsql data."""

FAKE_INSTANCE_RESPONSE_1 = [{"kind": "compute#networkInterface", "name": "nic0", "network": "https://www.googleapis.com/compute/v1/projects/xpn-master/global/networks/xpn-network", "networkIP": "10.174.3.93", "subnetwork": "https://www.googleapis.com/compute/v1/projects/xpn-master/regions/us-central1/subnetworks/xpn-usc1"}]
FAKE_INSTANCE_RESPONSE_2 = [{"kind": "compute#networkInterface", "name": "nic0", "network": "https://www.googleapis.com/compute/v1/projects/xpn-master/global/networks/xpn-network", "networkIP": "10.174.2.0", "subnetwork": "https://www.googleapis.com/compute/v1/projects/xpn-master/regions/us-central1/subnetworks/xpn-usc1", "accessConfigs": [{"kind": "compute#accessConfig", "name": "EXTERNAL NAT", "type": "ONE_TO_ONE_NAT", "natIP": "104.197.66.255"}]}] 

EXPECTED_FAKE_INSTANCE_FROM_API_1 = [deepcopy(FAKE_INSTANCE_NETWORK_RESPONSE_1)]
EXPECTED_FAKE_INSTANCE_FROM_API_2 = [deepcopy(FAKE_INSTANCE_NETWORK_RESPONSE_2)]
