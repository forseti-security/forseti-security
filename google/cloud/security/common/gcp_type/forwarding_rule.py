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

"""A Compute Forwarding Rule.

See: https://cloud.google.com/compute/docs/reference/latest/forwardingRules
"""

from google.cloud.security.common.util import parser

# pylint: disable=too-many-instance-attributes
class ForwardingRule(object):
    """Represents ForwardRule resource."""

    def __init__(self, **kwargs):
        """Forwarding rule resource.

        Args:
            **kwargs (dict): The object's attributes.
        """
        self.project_id = kwargs.get('project_id')
        self.resource_id = kwargs.get('id')
        self.creation_timestamp = kwargs.get('creation_timestamp')
        self.name = kwargs.get('name')
        self.description = kwargs.get('description')
        self.region = kwargs.get('region')
        self.ip_address = kwargs.get('ip_address')
        self.ip_protocol = kwargs.get('ip_protocol')
        self.port_range = kwargs.get('port_range')
        self.ports = parser.json_unstringify(kwargs.get('ports', '[]'))
        self.target = kwargs.get('target')
        self.self_link = kwargs.get('self_link')
        self.load_balancing_scheme = kwargs.get('load_balancing_scheme')
        self.subnetwork = kwargs.get('subnetwork')
        self.network = kwargs.get('network')
        self.backend_service = kwargs.get('backend_service')
