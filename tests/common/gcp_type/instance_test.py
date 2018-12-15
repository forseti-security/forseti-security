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

"""Test the Instance."""

from tests.common.gcp_type.test_data import fake_instance
from tests.unittest_utils import ForsetiTestCase
from google.cloud.forseti.common.gcp_type import instance


class InstanceTest(ForsetiTestCase):
    """Test Instance class."""

    def test_network_interface_creation(self):
        """Test that network_interface creation is correct."""
        network_interfaces = (instance.Instance(
           'name-0', **fake_instance.FAKE_INSTANCE_RESPONSE_1)
                              .create_network_interfaces())

        self.assertEqual(len(network_interfaces), 1)
        network_interface = network_interfaces[0]
        self.assertEqual('compute#networkInterface', network_interface.kind)
        self.assertEqual('nic0', network_interface.name)
        self.assertEqual('https://www.googleapis.com/compute/v1/projects/'
                         'project-1/global/networks/network-1',
                         network_interface.network)
        self.assertEqual('000.000.000.000', network_interface.network_ip)
        self.assertEqual('https://www.googleapis.com/compute/v1/projects'
                         '/project-1/regions/datacenter'
                         '/subnetworks/subnetwork-1',
                         network_interface.subnetwork)
        self.assertEqual([{u'kind': u'compute#accessConfig',
                           u'type': u'ONE_TO_ONE_NAT', u'name': u'External NAT',
                           u'natIP': u'000.000.000.001'}],
                         network_interface.access_configs)

    def test_recognize_two_network_interfaces(self):
        """Test that it recognizes two network_interfaces."""
        network_interfaces = (instance.Instance(
           'name-1', **fake_instance.FAKE_INSTANCE_RESPONSE_2)
                              .create_network_interfaces())
        self.assertEqual(len(network_interfaces), 2)

    def test_legacy_networks(self):
        """ Test legacy networks without a subnet works."""
        network_interfaces = (instance.Instance(
            'name-0', **fake_instance.FAKE_INSTANCE_RESPONSE_LEGACY)
                              .create_network_interfaces())
        self.assertEqual(len(network_interfaces), 1)
        network_interface = network_interfaces[0]
        self.assertEqual('compute#networkInterface', network_interface.kind)
        self.assertEqual('nic0', network_interface.name)
        self.assertEqual('https://www.googleapis.com/compute/v1/projects/'
                         'project-1/global/networks/network-1',
                         network_interface.network)
        self.assertEqual('000.000.000.000', network_interface.network_ip)
        self.assertEqual([{u'kind': u'compute#accessConfig',
                           u'type': u'ONE_TO_ONE_NAT', u'name': u'External NAT',
                           u'natIP': u'000.000.000.001'}],
                         network_interface.access_configs)

if __name__ == '__main__':
    unittest.main()
