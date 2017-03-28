# Copyright 2017 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Wrapper for Compute API client."""

import httplib
import socket

from google.cloud.security.common.gcp_api._base_client import _BaseClient

def is_compute_engine_instance():
    """Attempt to query the metadata server to determine if GCE instance.

    Returns:
        Tuple of (is_gce_instance, error_msg)
    """
    conn = httplib.HTTPConnection('metadata.google.internal', timeout=2)
    error_msg = None
    is_gce_instance = False
    try:
        conn.request('GET', '/computeMetadata/v1/instance/id',
                     None, {'Metadata-Flavor': 'Google'})
        res = conn.getresponse()

        if res and res.status == 200:
            is_gce_instance = True
        else:
            error_msg = res.reason
    except socket.error:
        error_msg = 'Unable to query metadata server'
    finally:
        conn.close()

    return (is_gce_instance, error_msg)

# pylint: disable=too-few-public-methods
class ComputeClient(_BaseClient):
    """Compute Client."""

    API_NAME = 'compute'

    def __init__(self, credentials=None):
        super(ComputeClient, self).__init__(
            credentials=credentials, api_name=self.API_NAME)

    # TODO: Migrate helper functions from gce_firewall_enforcer.py
    # ComputeFirewallAPI class.
