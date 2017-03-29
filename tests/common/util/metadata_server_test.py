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

"""Tests the Metadata Server utility."""

import httplib
import mock
import socket

from google.apputils import basetest
from google.cloud.security.common.util import metadata_server


def _default_side_effect(*args, **kwargs):
    return mock.DEFAULT


class _MockHttpError(socket.error):
    """Mock Http Error"""
    pass


class MetadataServerTest(basetest.TestCase):
    """Test the Metadata Server util."""

    @mock.patch.object(httplib.HTTPConnection, 'request', autospec=True)
    def test_can_reach_metadata_server(self, mock_req):
        """Test that the return value is True when metadata server is reachable.

        Setup:
            * Patch the HTTPConnection request() method not to throw an
              Exception due to an unreachable server.
            * Patch the HTTPConnection getresponse() method's status property.
        Expected results:
            Method call returns True.
        """
        mock_req.side_effect = _default_side_effect
        with mock.patch('httplib.HTTPConnection.getresponse') as mock_res:
            mock_res.side_effect = _default_side_effect
            mock_res.return_value.status = 200
            actual_response = metadata_server.can_reach_metadata_server()
        self.assertTrue(actual_response)

    @mock.patch.object(httplib.HTTPConnection, 'request', autospec=True)
    def test_cannot_reach_metadata_server(self, mock_req):
        """Test return value is False when metadata server is unreachable.

        Setup:
            * Patch the HTTPConnection request() method to throw an
              Exception due to an unreachable server.
        Expected results:
            Method call returns False.
        """
        mock_req.side_effect = _MockHttpError('Unreachable')
        actual_response = metadata_server.can_reach_metadata_server()
        self.assertFalse(actual_response)


if __name__ == '__main__':
    basetest.main()
