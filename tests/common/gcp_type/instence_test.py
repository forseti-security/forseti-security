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

"""Test the Instance."""

from tests.unittest_utils import ForsetiTestCase
from google.cloud.security.common.gcp_type import instance
from tests.common.gcp_type.test_data import fake_instance


class InstanceTest(ForsetiTestCase):
    """Test IAM Policy class."""

    def test_network_interface_creation(self):
        """Test that network_interface creation is correct."""
        network_interfaces = instance.Instance(
            **fake_instance.FAKE_INSTANCE_RESPONSE_1)\
            .create_network_interfaces()

        self.assertEqual(len(network_interfaces), 1)
        nw = network_interfaces[0]
        self.assertEqual('compute#networkInterface', nw.kind)
        self.assertEqual('nic0', nw.name)
        self.assertEqual('https://www.googleapis.com/compute/v1/projects/'
                         'xpn-master/global/networks/xpn-network', nw.network)
        self.assertEqual('10.175.3.132', nw.networkIP)
        self.assertEqual('https://www.googleapis.com/compute/v1/projects'
                         '/xpn-master/regions/asia-east1/subnetworks/xpn-ase1',
                         nw.subnetwork)
        self.assertEqual([{u'kind': u'compute#accessConfig',
                         u'type': u'ONE_TO_ONE_NAT', u'name': u'External NAT',
                          u'natIP': u'104.199.244.119'}], nw.accessConfigs)

    def test_recognizes_two_network_interfaces(self):
        """Test that it recognizes two network_interfaces."""
        network_interfaces = instance.Instance(
            **fake_instance.FAKE_INSTANCE_RESPONSE_2) \
            .create_network_interfaces()
        self.assertEqual(len(network_interfaces), 2)

if __name__ == '__main__':
    unittest.main()
