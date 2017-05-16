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

"""Test data for firewall api responses."""


PAGED_RESULTS = [
    {u'id': u'projects/forseti-henry-remote/global/firewalls',
     u'items': [
         {u'allowed': [{u'IPProtocol': u'icmp1'}]},
         {u'allowed': [{u'IPProtocol': u'tcp', u'ports': [u'3389']}]}
     ],
     u'kind': u'compute#firewallList'},
    {u'id': u'projects/forseti-henry-remote/global/firewalls',
     u'items': [
         {u'allowed': [{u'IPProtocol': u'icmp2'}]},
         {u'allowed': [{u'IPProtocol': u'tcp', u'ports': [u'3390']}]}
     ],
     u'kind': u'compute#firewallList'},                 
]

EXPECTED_RESULTS = [
    {u'allowed': [{u'IPProtocol': u'icmp1'}]},
    {u'allowed': [{u'IPProtocol': u'tcp', u'ports': [u'3389']}]},
    {u'allowed': [{u'IPProtocol': u'icmp2'}]},
    {u'allowed': [{u'IPProtocol': u'tcp', u'ports': [u'3390']}]}
]