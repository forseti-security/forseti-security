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

"""Tests the Compute client."""

import httplib
import mock
import socket

from google.apputils import basetest
from google.cloud.security.common.gcp_api import compute
from google.cloud.security.common.gcp_api.errors import InvalidBucketPathError
from google.cloud.security.common.gcp_type.resource_util import ResourceUtil


def _default_side_effect(*args, **kwargs):
    return mock.DEFAULT


class _MockHttpError(socket.error):
    """Mock Http Error"""
    pass


class ComputeTest(basetest.TestCase):
    """Test the ComputeEngine client."""

    @mock.patch.object(httplib.HTTPConnection, 'request', autospec=True)
    def test_on_gce_returns_true(self, mock_req):
        """Test that the return value is True when metadata server is reachable.

        Setup:
            * Patch the HTTPConnection request() method not to throw an
              Exception due to an unreachable server.
            * Patch the HTTPConnection getresponse() method's status and
              reason properties.
        Expected results:
            Method call returns (True, None).
        """
        mock_req.side_effect = _default_side_effect
        with mock.patch('httplib.HTTPConnection.getresponse') as mock_res:
            mock_res.side_effect = _default_side_effect
            mock_res.return_value.status = 200
            mock_res.return_value.reason = None
            actual_response = compute.is_compute_engine_instance()
        self.assertEqual((True, None), actual_response)

    @mock.patch.object(httplib.HTTPConnection, 'request', autospec=True)
    def test_not_on_gce_returns_false(self, mock_req):
        """Test return value is False when metadata server is unreachable.

        Setup:
            * Patch the HTTPConnection request() method to throw an
              Exception due to an unreachable server.
        Expected results:
            Method call returns (False, 'Unable to query metadata server').
        """
        mock_req.side_effect = _MockHttpError('Unreachable')
        actual_response = compute.is_compute_engine_instance()
        self.assertEqual((False, 'Unable to query metadata server'),
                         actual_response)


if __name__ == '__main__':
    basetest.main()
