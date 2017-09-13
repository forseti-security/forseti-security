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

"""Sample data used in testing gce_enforcer.

Consists exclusively of test constants.
"""

TEST_PROJECT = "test-project"
TEST_NETWORK = "test-network"

SAMPLE_TEST_NETWORK_SELFLINK = {
    "items": [
        {
            "selfLink": (u"https://www.googleapis.com/compute/beta/projects/"
                         "test-project/global/networks/test-network")
        },
    ]
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

EXPECTED_FIREWALL_API_RESPONSE = {
    "id":
        u"projects/test-project/global/firewalls",
    "items": [{
        "sourceRanges": [u"10.8.0.0/24"],
        "creationTimestamp":
            u"2015-09-04T14:03:38.591-07:00",
        "id":
            u"3140311180993083845",
        "kind":
            u"compute#firewall",
        "description":
            u"Allow communication between instances.",
        "network": (u"https://www.googleapis.com/compute/beta/projects/"
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
        "name":
            u"test-network-allow-internal-1"
    }, {
        "sourceRanges": [u"10.0.0.0/8"],
        "description": (u"Allow internal traffic from a range of IP "
                        "addresses."),
        "network": (u"https://www.googleapis.com/compute/beta/projects/"
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
        "name":
            u"test-network-allow-internal-0"
    }, {
        "sourceRanges": [u"127.0.0.1/32", u"127.0.0.2/32"],
        "description":
            u"Allow public traffic from specific IP addresses.",
        "network": (u"https://www.googleapis.com/compute/beta/projects/"
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
        "name":
            u"test-network-allow-public-0"
    }],
    "kind":
        u"compute#firewallList",
    "selfLink": (
        u"https://www.googleapis.com/compute/beta/projects/test-project/global/"
        "firewalls")
}

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
        "network": (u"https://www.googleapis.com/compute/beta/projects/"
                    "test-project/global/networks/test-network"),
        "sourceRanges": [u"10.8.0.0/24"],
        "priority": 1000,
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
        "network": (u"https://www.googleapis.com/compute/beta/projects/"
                    "test-project/global/networks/test-network"),
        "sourceRanges": [u"10.0.0.0/8"],
        "priority": 1000,
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
        "network": (u"https://www.googleapis.com/compute/beta/projects/"
                    "test-project/global/networks/test-network"),
        "sourceRanges": [u"127.0.0.1/32", u"127.0.0.2/32"],
        "priority": 1000,
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

DEFAULT_FIREWALL_API_RESPONSE = {
    "id":
        u"projects/test-project/global/firewalls",
    "items": [{
        "sourceRanges": [u"0.0.0.0/0"],
        "creationTimestamp":
            u"2015-09-04T14:03:38.591-07:00",
        "id":
            u"3140311180993083845",
        "kind":
            u"compute#firewall",
        "description":
            u"Allow ICMP from anywhere",
        "network": (u"https://www.googleapis.com/compute/beta/projects/"
                    "test-project/global/networks/test-network"),
        "allowed": [{
            "IPProtocol": u"icmp"
        }],
        "name":
            u"test-network-allow-icmp"
    }, {
        "sourceRanges": [u"10.240.0.0/16"],
        "description": (u"Allow internal traffic on the default network."),
        "network": (u"https://www.googleapis.com/compute/beta/projects/"
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
        "name":
            u"test-network-allow-internal"
    }, {
        "sourceRanges": [u"0.0.0.0/0"],
        "description":
            u"Allow RDP from anywhere",
        "network": (u"https://www.googleapis.com/compute/beta/projects/"
                    "test-project/global/networks/test-network"),
        "allowed": [
            {
                "IPProtocol": u"tcp",
                "ports": [u"3389"]
            },
        ],
        "name":
            u"test-network-allow-rdp"
    }, {
        "sourceRanges": [u"0.0.0.0/0"],
        "description":
            u"Allow SSH from anywhere",
        "network": (u"https://www.googleapis.com/compute/beta/projects/"
                    "test-project/global/networks/test-network"),
        "allowed": [
            {
                "IPProtocol": u"tcp",
                "ports": [u"22"]
            },
        ],
        "name":
            u"test-network-allow-ssh"
    }],
    "kind":
        u"compute#firewallList",
    "selfLink": (
        u"https://www.googleapis.com/compute/beta/projects/test-project/global/"
        "firewalls")
}

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
        "network": (u"https://www.googleapis.com/compute/beta/projects/"
                    "test-project/global/networks/test-network"),
        "allowed": [{
            "IPProtocol": u"icmp"
        }],
        "name":
            u"test-network-allow-icmp"
    },
    u"test-network-allow-internal": {
        "sourceRanges": [u"10.240.0.0/16"],
        "description": (u"Allow internal traffic on the default network."),
        "network": (u"https://www.googleapis.com/compute/beta/projects/"
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
        "name":
            u"test-network-allow-internal"
    },
    u"test-network-allow-rdp": {
        "sourceRanges": [u"0.0.0.0/0"],
        "description":
            u"Allow RDP from anywhere",
        "network": (u"https://www.googleapis.com/compute/beta/projects/"
                    "test-project/global/networks/test-network"),
        "allowed": [
            {
                "IPProtocol": u"tcp",
                "ports": [u"3389"]
            },
        ],
        "name":
            u"test-network-allow-rdp"
    },
    u"test-network-allow-ssh": {
        "sourceRanges": [u"0.0.0.0/0"],
        "description":
            u"Allow SSH from anywhere",
        "network": (u"https://www.googleapis.com/compute/beta/projects/"
                    "test-project/global/networks/test-network"),
        "allowed": [
            {
                "IPProtocol": u"tcp",
                "ports": [u"22"]
            },
        ],
        "name":
            u"test-network-allow-ssh"
    }
}

SAMPLE_ENFORCER_PROJECTRESULTS_ASCIIPB = """
  project_id: 'test-project'
  timestamp_sec: 1234567890
  batch_id: 1234567890
  run_context: ENFORCER_BATCH
  status: SUCCESS
  gce_firewall_enforcement {
    rules_before {
      json: '[{"allowed": [{"IPProtocol": "icmp"}], "description": '
            '"Allow ICMP from anywhere", "direction": "INGRESS", '
            '"name": "test-network-allow-icmp", '
            '"network": "https://www.googleapis.com/compute/beta/projects/'
            'test-project/global/networks/test-network", "priority": 1000, '
            '"sourceRanges": '
            '["0.0.0.0/0"]}, {"allowed": [{"IPProtocol": "icmp"}, '
            '{"IPProtocol": "tcp", "ports": ["1-65535"]}, {"IPProtocol": '
            '"udp", "ports": ["1-65535"]}], "description": "Allow internal '
            'traffic on the default network.", "direction": "INGRESS", "name": '
            '"test-network-allow-internal", "network": '
            '"https://www.googleapis.com/compute/beta/projects/test-project/'
            'global/networks/test-network", "priority": 1000, "sourceRanges": '
            '["10.240.0.0/16"]},'
            ' {"allowed": [{"IPProtocol": "tcp", "ports": ["3389"]}], '
            '"description": "Allow RDP from anywhere", "direction": "INGRESS", '
            '"name": '
            '"test-network-allow-rdp", "network": '
            '"https://www.googleapis.com/compute/beta/projects/test-project/'
            'global/networks/test-network", "priority": 1000, "sourceRanges": '
            '["0.0.0.0/0"]}, '
            '{"allowed": [{"IPProtocol": "tcp", "ports": ["22"]}], '
            '"description": "Allow SSH from anywhere", "direction": "INGRESS", '
            '"name": '
            '"test-network-allow-ssh", "network": '
            '"https://www.googleapis.com/compute/beta/projects/test-project/'
            'global/networks/test-network", "priority": 1000, "sourceRanges": '
            '["0.0.0.0/0"]}]'
      hash: "b589a2f63159e3450e07e9437fcda83c3dc3c343873bfb4c5c12f1a391ea9813"
    }
    rules_after {
      json: '[{"allowed": [{"IPProtocol": "icmp"}, {"IPProtocol": "tcp", '
            '"ports": ["1-65535"]}, {"IPProtocol": "udp", "ports": ["1-65535"]'
            '}], "description": "Allow internal traffic from a range of IP '
            'addresses.", "direction": "INGRESS", '
            '"name": "test-network-allow-internal-0", "network": '
            '"https://www.googleapis.com/compute/beta/projects/test-project/'
            'global/networks/test-network", "priority": 1000, "sourceRanges": '
            '["10.0.0.0/8"]}, '
            '{"allowed": [{"IPProtocol": "icmp"}, {"IPProtocol": "tcp", '
            '"ports": ["1-65535"]}, {"IPProtocol": "udp", "ports": ["1-65535"]'
            '}], "description": "Allow communication between instances.", '
            '"direction": "INGRESS", "name": "test-network-allow-internal-1", '
            '"network": '
            '"https://www.googleapis.com/compute/beta/projects/test-project/'
            'global/networks/test-network", "priority": 1000, "sourceRanges": '
            '["10.8.0.0/24"]}, '
            '{"allowed": [{"IPProtocol": "ah"}, {"IPProtocol": "esp"}, '
            '{"IPProtocol": "tcp", "ports": ["22"]}, {"IPProtocol": "udp", '
            '"ports": ["9999"]}], "description": "Allow public traffic from '
            'specific IP addresses.", "direction": "INGRESS", '
            '"name": "test-network-allow-public-0", '
            '"network": "https://www.googleapis.com/compute/beta/projects/'
            'test-project/global/networks/test-network", "priority": 1000, '
            '"sourceRanges": '
            '["127.0.0.1/32", "127.0.0.2/32"]}]'
      hash: "698e6912c23c5f4dee9008ce63ca1cb26da3bcd4c6bac1ab9118a744b18718ec"
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

