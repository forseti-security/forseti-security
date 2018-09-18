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


DIRECTION_ENCODING = {
    'INGRESS': [0, 1],
    'EGRESS': [1, 0]
}


class FirewallRule(object):
    """Flattened firewall rule."""
    def __init__(self):
        self.creation_timestamp = ''
        # "creationTimestamp": "2018-02-28T21:49:07.739-08:00"

        self.description = ''
        # "description": ""

        self.name = ''
        # "name": "forseti-server-allow-grpc-20180228211432",

        self.network = ''
        # "network": "https://www.googleapis.com/compute/beta/projects/joe-project-p2/global/networks/default"

        self.priority = 0
        # "priority": 0

        self.source_ranges = 0
        # "sourceRanges": ["10.128.0.0/9"]

        self.destination_ranges = 0
        # "destinationRanges": ["10.128.0.0/9"]

        self.source_tags = []

        self.target_tags = []

        self.source_service_accounts = []

        self.target_service_accounts = []
        # targetServiceAccounts": ["forseti-gcp-server-1432@joe-project-p2.iam.gserviceaccount.com"]}"

        self.allowed = []
        # "allowed": [{"IPProtocol": "tcp", "ports": ["50051"]}]

        self.denied = []

        self.direction = ''
        # "direction": "INGRESS"

        self.disabled = True
        # "disabled": false
