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

"""Sample data and base class used in testing enforcer."""

from datetime import datetime
import json
import mock
from tests.unittest_utils import ForsetiTestCase
import google.auth
from google.cloud.forseti.common.gcp_api import compute
from google.cloud.forseti.common.util import date_time
from google.oauth2 import credentials

# Used anywhere a real timestamp could be generated to ensure consistent
# comparisons in tests
MOCK_MICROTIMESTAMP = 1514764800123456
MOCK_DATETIME = datetime(2018, 1, 1, 0, 0, 0, 123456)

TEST_PROJECT = "test-project"
TEST_NETWORK = "test-network"

SAMPLE_TEST_NETWORK_SELFLINK = [
    {
        "selfLink": (u"https://www.googleapis.com/compute/v1/projects/"
                     "test-project/global/networks/test-network")
    },
]

TEST_PROJECT_RESPONSE = {
    "kind": "compute#project",
    "id": "1111111",
    "creationTimestamp": "2016-02-25T14:01:23.140-08:00",
    "name": "test-project",
    "quotas": [
        {
            "metric": "FIREWALLS",
            "limit": 100.0,
            "usage": 9.0
        }
    ],
    "selfLink": "https://www.googleapis.com/compute/v1/projects/test-project",
    "defaultServiceAccount": "1111111-compute@developer.gserviceaccount.com",
    "xpnProjectStatus": "UNSPECIFIED_XPN_PROJECT_STATUS"
}

RAW_EXPECTED_JSON_POLICY = """
  [
    {
      "sourceRanges": [
        "10.8.0.0/24"
      ],
      "description": "Allow communication between instances.",
      "allowed": [
        {
          "IPProtocol": "udp",
          "ports": [
            "1-65535"
          ]
        },
        {
          "IPProtocol": "tcp",
          "ports": [
            "1-65535"
          ]
        },
        {
          "IPProtocol": "icmp"
        }
      ],
      "name": "allow-internal-1"
    },
    {
      "sourceRanges": [
        "10.0.0.0/8"
      ],
      "description": "Allow internal traffic from a range of IP addresses.",
      "allowed": [
        {
          "IPProtocol": "udp",
          "ports": [
            "1-65535"
          ]
        },
        {
          "IPProtocol": "tcp",
          "ports": [
            "1-65535"
          ]
        },
        {
          "IPProtocol": "icmp"
        }
      ],
      "name": "allow-internal-0"
    },
    {
      "sourceRanges": [
        "127.0.0.1/32",
        "127.0.0.2/32"
      ],
      "description": "Allow public traffic from specific IP addresses.",
      "allowed": [
        {
          "IPProtocol": "tcp",
          "ports": [
            "22"
          ]
        },
        {
          "IPProtocol": "udp",
          "ports": [
            "9999"
          ]
        },
        {
          "IPProtocol": "esp"
        },
        {
          "IPProtocol": "ah"
        }
      ],
      "name": "allow-public-0"
    }
  ]
"""

EXPECTED_FIREWALL_API_RESPONSE = [
    {
        "sourceRanges": [u"10.8.0.0/24"],
        "creationTimestamp":
            u"2015-09-04T14:03:38.591-07:00",
        "id":
            u"3140311180993083845",
        "kind":
            u"compute#firewall",
        "description":
            u"Allow communication between instances.",
        "network": (u"https://www.googleapis.com/compute/v1/projects/"
                    "test-project/global/networks/test-network"),
        "allowed": [{
            "IPProtocol": u"udp",
            "ports": [u"1-65535"]
        }, {
            "IPProtocol": u"tcp",
            "ports": [u"1-65535"]
        }, {
            "IPProtocol": u"icmp"
        }],
        "direction": "INGRESS",
        "disabled": False,
        "priority": 1000,
        "logConfig": {"enable": False},
        "name":
            u"test-network-allow-internal-1"
    }, {
        "sourceRanges": [u"10.0.0.0/8"],
        "description": (u"Allow internal traffic from a range of IP "
                        "addresses."),
        "network": (u"https://www.googleapis.com/compute/v1/projects/"
                    "test-project/global/networks/test-network"),
        "allowed": [{
            "IPProtocol": u"udp",
            "ports": [u"1-65535"]
        }, {
            "IPProtocol": u"tcp",
            "ports": [u"1-65535"]
        }, {
            "IPProtocol": u"icmp"
        }],
        "direction": "INGRESS",
        "disabled": False,
        "priority": 1000,
        "logConfig": {"enable": False},
        "name":
            u"test-network-allow-internal-0"
    }, {
        "sourceRanges": [u"127.0.0.1/32", u"127.0.0.2/32"],
        "description":
            u"Allow public traffic from specific IP addresses.",
        "network": (u"https://www.googleapis.com/compute/v1/projects/"
                    "test-project/global/networks/test-network"),
        "allowed": [{
            "IPProtocol": u"tcp",
            "ports": [u"22"]
        }, {
            "IPProtocol": u"udp",
            "ports": [u"9999"]
        }, {
            "IPProtocol": u"esp"
        }, {
            "IPProtocol": u"ah"
        }],
        "direction": "INGRESS",
        "disabled": False,
        "priority": 1000,
        "logConfig": {"enable": False},
        "name":
            u"test-network-allow-public-0"
    }
]

EXPECTED_FIREWALL_RULES = {
    "test-network-allow-internal-1": {
        "allowed": [{
            "IPProtocol": u"icmp"
        }, {
            "IPProtocol": u"tcp",
            "ports": [u"1-65535"]
        }, {
            "IPProtocol": u"udp",
            "ports": [u"1-65535"]
        }],
        "description":
            u"Allow communication between instances.",
        "name":
            u"test-network-allow-internal-1",
        "network": (u"https://www.googleapis.com/compute/v1/projects/"
                    "test-project/global/networks/test-network"),
        "sourceRanges": [u"10.8.0.0/24"],
        "priority": 1000,
        "logConfig": {"enable": False},
        "disabled": False,
        "direction": "INGRESS"},
    "test-network-allow-internal-0": {
        "allowed": [{
            "IPProtocol": u"icmp"
        }, {
            "IPProtocol": u"tcp",
            "ports": [u"1-65535"]
        }, {
            "IPProtocol": u"udp",
            "ports": [u"1-65535"]
        }],
        "description": (u"Allow internal traffic from a range of IP "
                        "addresses."),
        "name":
            u"test-network-allow-internal-0",
        "network": (u"https://www.googleapis.com/compute/v1/projects/"
                    "test-project/global/networks/test-network"),
        "sourceRanges": [u"10.0.0.0/8"],
        "priority": 1000,
        "logConfig": {"enable": False},
        "disabled": False,
        "direction": "INGRESS"},
    "test-network-allow-public-0": {
        "allowed": [{
            "IPProtocol": u"ah"
        }, {
            "IPProtocol": u"esp"
        }, {
            "IPProtocol": u"tcp",
            "ports": [u"22"]
        }, {
            "IPProtocol": u"udp",
            "ports": [u"9999"]
        }],
        "description":
            u"Allow public traffic from specific IP addresses.",
        "name":
            u"test-network-allow-public-0",
        "network": (u"https://www.googleapis.com/compute/v1/projects/"
                    "test-project/global/networks/test-network"),
        "sourceRanges": [u"127.0.0.1/32", u"127.0.0.2/32"],
        "priority": 1000,
        "logConfig": {"enable": False},
        "disabled": False,
        "direction": "INGRESS"},
}


RAW_DEFAULT_JSON_POLICY = """
    [
        {
            "sourceRanges": ["0.0.0.0/0"],
            "description": "Allow ICMP from anywhere",
            "allowed": [
                {
                    "IPProtocol": "icmp"
                }
            ],
            "name": "allow-icmp"
        },
        {
            "sourceRanges": ["10.240.0.0/16"],
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
            "name": "allow-internal"
        },
        {
            "sourceRanges": ["0.0.0.0/0"],
            "description": "Allow RDP from anywhere",
            "allowed": [
                {
                    "IPProtocol": "tcp",
                    "ports": ["3389"]
                }
            ],
            "name": "allow-rdp"
        },
        {
            "sourceRanges": ["0.0.0.0/0"],
            "description": "Allow SSH from anywhere",
            "allowed": [
                {
                    "IPProtocol": "tcp",
                    "ports": ["22"]
                }
            ],
            "name": "allow-ssh"
        }
    ]
"""

DEFAULT_FIREWALL_API_RESPONSE = [
    {
        "sourceRanges": [u"0.0.0.0/0"],
        "creationTimestamp":
            u"2015-09-04T14:03:38.591-07:00",
        "id":
            u"3140311180993083845",
        "kind":
            u"compute#firewall",
        "description":
            u"Allow ICMP from anywhere",
        "network": (u"https://www.googleapis.com/compute/v1/projects/"
                    "test-project/global/networks/test-network"),
        "allowed": [{
            "IPProtocol": u"icmp"
        }],
        "disabled": False,
        "logConfig": {"enable": False},
        "name":
            u"test-network-allow-icmp"
    }, {
        "sourceRanges": [u"10.240.0.0/16"],
        "description": (u"Allow internal traffic on the default network."),
        "network": (u"https://www.googleapis.com/compute/v1/projects/"
                    "test-project/global/networks/test-network"),
        "allowed": [{
            "IPProtocol": u"udp",
            "ports": [u"1-65535"]
        }, {
            "IPProtocol": u"tcp",
            "ports": [u"1-65535"]
        }, {
            "IPProtocol": u"icmp"
        }],
        "disabled": False,
        "logConfig": {"enable": False},
        "name":
            u"test-network-allow-internal"
    }, {
        "sourceRanges": [u"0.0.0.0/0"],
        "description":
            u"Allow RDP from anywhere",
        "network": (u"https://www.googleapis.com/compute/v1/projects/"
                    "test-project/global/networks/test-network"),
        "allowed": [
            {
                "IPProtocol": u"tcp",
                "ports": [u"3389"]
            },
        ],
        "disabled": False,
        "logConfig": {"enable": False},
        "name":
            u"test-network-allow-rdp"
    }, {
        "sourceRanges": [u"0.0.0.0/0"],
        "description":
            u"Allow SSH from anywhere",
        "network": (u"https://www.googleapis.com/compute/v1/projects/"
                    "test-project/global/networks/test-network"),
        "allowed": [
            {
                "IPProtocol": u"tcp",
                "ports": [u"22"]
            },
        ],
        "disabled": False,
        "logConfig": {"enable": False},
        "name":
            u"test-network-allow-ssh"
    }
]

DEFAULT_FIREWALL_RULES = {
    u"test-network-allow-icmp": {
        "sourceRanges": [u"0.0.0.0/0"],
        "creationTimestamp":
            u"2015-09-04T14:03:38.591-07:00",
        "id":
            u"3140311180993083845",
        "kind":
            u"compute#firewall",
        "description":
            u"Allow ICMP from anywhere",
        "network": (u"https://www.googleapis.com/compute/v1/projects/"
                    "test-project/global/networks/test-network"),
        "allowed": [{
            "IPProtocol": u"icmp"
        }],
        "disabled": False,
        "logConfig": {"enable": False},
        "name":
            u"test-network-allow-icmp"
    },
    u"test-network-allow-internal": {
        "sourceRanges": [u"10.240.0.0/16"],
        "description": (u"Allow internal traffic on the default network."),
        "network": (u"https://www.googleapis.com/compute/v1/projects/"
                    "test-project/global/networks/test-network"),
        "allowed": [{
            "IPProtocol": u"udp",
            "ports": [u"1-65535"]
        }, {
            "IPProtocol": u"tcp",
            "ports": [u"1-65535"]
        }, {
            "IPProtocol": u"icmp"
        }],
        "disabled": False,
        "logConfig": {"enable": False},
        "name":
            u"test-network-allow-internal"
    },
    u"test-network-allow-rdp": {
        "sourceRanges": [u"0.0.0.0/0"],
        "description":
            u"Allow RDP from anywhere",
        "network": (u"https://www.googleapis.com/compute/v1/projects/"
                    "test-project/global/networks/test-network"),
        "allowed": [
            {
                "IPProtocol": u"tcp",
                "ports": [u"3389"]
            },
        ],
        "logConfig": {"enable": False},
        "disabled": False,
        "name":
            u"test-network-allow-rdp"
    },
    u"test-network-allow-ssh": {
        "sourceRanges": [u"0.0.0.0/0"],
        "description":
            u"Allow SSH from anywhere",
        "network": (u"https://www.googleapis.com/compute/v1/projects/"
                    "test-project/global/networks/test-network"),
        "allowed": [
            {
                "IPProtocol": u"tcp",
                "ports": [u"22"]
            },
        ],
        "logConfig": {"enable": False},
        "disabled": False,
        "name":
            u"test-network-allow-ssh"
    }
}

SAMPLE_ENFORCER_PROJECTRESULTS_ASCIIPB = """
  project_id: 'test-project'
  timestamp_sec: 1514764800123456
  batch_id: 1514764800123456
  run_context: ENFORCER_BATCH
  status: SUCCESS
  gce_firewall_enforcement {
    rules_before {
      json: '[{"allowed": [{"IPProtocol": "icmp"}], "description": '
            '"Allow ICMP from anywhere", "direction": "INGRESS", '
            '"disabled": false, "logConfig": {"enable": false}, '
            '"name": "test-network-allow-icmp", '
            '"network": "https://www.googleapis.com/compute/v1/projects/'
            'test-project/global/networks/test-network", "priority": 1000, '
            '"sourceRanges": '
            '["0.0.0.0/0"]}, {"allowed": [{"IPProtocol": "icmp"}, '
            '{"IPProtocol": "tcp", "ports": ["1-65535"]}, {"IPProtocol": '
            '"udp", "ports": ["1-65535"]}], "description": "Allow internal '
            'traffic on the default network.", "direction": "INGRESS", '
            '"disabled": false, '
            '"logConfig": {"enable": false}, '
            '"name": "test-network-allow-internal", "network": '
            '"https://www.googleapis.com/compute/v1/projects/test-project/'
            'global/networks/test-network", "priority": 1000, "sourceRanges": '
            '["10.240.0.0/16"]},'
            ' {"allowed": [{"IPProtocol": "tcp", "ports": ["3389"]}], '
            '"description": "Allow RDP from anywhere", "direction": "INGRESS", '
            '"disabled": false, '
            '"logConfig": {"enable": false}, '
            '"name": "test-network-allow-rdp", "network": '
            '"https://www.googleapis.com/compute/v1/projects/test-project/'
            'global/networks/test-network", "priority": 1000, "sourceRanges": '
            '["0.0.0.0/0"]}, '
            '{"allowed": [{"IPProtocol": "tcp", "ports": ["22"]}], '
            '"description": "Allow SSH from anywhere", "direction": "INGRESS", '
            '"disabled": false, '
            '"logConfig": {"enable": false}, '
            '"name": "test-network-allow-ssh", "network": '
            '"https://www.googleapis.com/compute/v1/projects/test-project/'
            'global/networks/test-network", "priority": 1000, "sourceRanges": '
            '["0.0.0.0/0"]}]'
      hash: "79736b5815ec9285d3281df4c7dfb59bb25d0972a19d591c0e17cdc0d70ff21f"
    }
    rules_after {
      json: '[{"allowed": [{"IPProtocol": "icmp"}, {"IPProtocol": "tcp", '
            '"ports": ["1-65535"]}, {"IPProtocol": "udp", "ports": ["1-65535"]'
            '}], "description": "Allow internal traffic from a range of IP '
            'addresses.", "direction": "INGRESS", '
            '"disabled": false, '
            '"logConfig": {"enable": false}, '
            '"name": "test-network-allow-internal-0", "network": '
            '"https://www.googleapis.com/compute/v1/projects/test-project/'
            'global/networks/test-network", "priority": 1000, "sourceRanges": '
            '["10.0.0.0/8"]}, '
            '{"allowed": [{"IPProtocol": "icmp"}, {"IPProtocol": "tcp", '
            '"ports": ["1-65535"]}, {"IPProtocol": "udp", "ports": ["1-65535"]'
            '}], "description": "Allow communication between instances.", '
            '"direction": "INGRESS", '
            '"disabled": false, '
            '"logConfig": {"enable": false}, '
            '"name": "test-network-allow-internal-1", '
            '"network": '
            '"https://www.googleapis.com/compute/v1/projects/test-project/'
            'global/networks/test-network", "priority": 1000, "sourceRanges": '
            '["10.8.0.0/24"]}, '
            '{"allowed": [{"IPProtocol": "ah"}, {"IPProtocol": "esp"}, '
            '{"IPProtocol": "tcp", "ports": ["22"]}, {"IPProtocol": "udp", '
            '"ports": ["9999"]}], "description": "Allow public traffic from '
            'specific IP addresses.", "direction": "INGRESS", '
            '"disabled": false, '
            '"logConfig": {"enable": false}, '
            '"name": "test-network-allow-public-0", '
            '"network": "https://www.googleapis.com/compute/v1/projects/'
            'test-project/global/networks/test-network", "priority": 1000, '
            '"sourceRanges": '
            '["127.0.0.1/32", "127.0.0.2/32"]}]'
      hash: "8e34ec2a6ab8a86dee8c6e98fc94cd9fe823a8732aa26e9438a281bc5fc326f8"
    }
    rules_added: "test-network-allow-internal-0"
    rules_added: "test-network-allow-internal-1"
    rules_added: "test-network-allow-public-0"
    rules_removed: "test-network-allow-icmp"
    rules_removed: "test-network-allow-internal"
    rules_removed: "test-network-allow-rdp"
    rules_removed: "test-network-allow-ssh"
    rules_modified_count: 7
    all_rules_changed: true
  }
"""


class EnforcerTestCase(ForsetiTestCase):
    """Base class for Enforcer."""

    @classmethod
    @mock.patch.object(
        google.auth, "default",
        return_value=(mock.Mock(spec_set=credentials.Credentials),
                      TEST_PROJECT))
    def setUpClass(cls, mock_google_credential):
        """Set up."""
        fake_global_configs = {
            "compute": {"max_calls": 18, "period": 1}}
        cls.gce_api_client = compute.ComputeClient(
            global_configs=fake_global_configs, dry_run=True)

    def setUp(self):
        """Set up."""
        self.mock_time = mock.patch.object(
            date_time, "get_utc_now_datetime", return_value=MOCK_DATETIME
        ).start()
        self.gce_api_client.get_networks = mock.Mock(
            return_value=SAMPLE_TEST_NETWORK_SELFLINK)
        self.gce_api_client.get_project = mock.Mock(
            return_value=TEST_PROJECT_RESPONSE)
        self.gce_api_client.get_firewall_rules = mock.Mock()
        self.project = TEST_PROJECT
        self.policy = json.loads(RAW_EXPECTED_JSON_POLICY)
