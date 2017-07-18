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
import json
import mock
import socket
import unittest

from tests.unittest_utils import ForsetiTestCase
from google.cloud.security.common.util import metadata_server
from google.cloud.security.common.util import errors

from StringIO import StringIO


class _MockHttpError(socket.error):
    """Mock Http Error"""
    pass


class _MockMetadataServerHttpError(errors.MetadataServerHttpError):
    """Mock MetadataServerHttpError"""
    pass


class MetadataServerTest(ForsetiTestCase):
    """Test the Metadata Server util."""

    @mock.patch.object(httplib.HTTPConnection, 'request', autospec=True)
    def test_issue_http_request_raises_metadatahttperror(self, mock_req):
        """Test _issue_http_request raises an exception with socket.error
        in httplib.HTTPConnection.request().

        Setup:
            * Insist httplib.HTTPConnection.request raises socket.error.

        Expected results:
            * metadata_server.MetadataServerHttpError is raised and asserted.
        """
        mock_req.side_effect = _MockHttpError('Unreachable')
        with self.assertRaises(errors.MetadataServerHttpError):
            metadata_server._issue_http_request('','',{})

    def test_obtain_http_client_returns_httplib_httpconnection_object(self):
        """Test _obtain_http_client returns the proper object.

        Expected results:
            * Assert a httplib.HTTPConnection object is returned.
        """
        returned_object = metadata_server._obtain_http_client()
        self.assertIsInstance(returned_object, httplib.HTTPConnection)

    @mock.patch.object(metadata_server, '_issue_http_request', autospec=True)
    def test_can_reach_metadata_server_with_valid_response(self, mock_meta_req):
        """Test can_reach_metadata_server returns True with a valid response.

        Setup:
            * Have httplib return a valid respone and response.status.

        Expected results:
            * A True result.
        """
        with mock.patch('httplib.HTTPResponse') as mock_http_resp:
            mock_http_resp.return_value.status = httplib.OK
            mock_meta_req.side_effect = mock_http_resp
            actual_response = metadata_server.can_reach_metadata_server()

        self.assertTrue(actual_response)

    @mock.patch.object(metadata_server, '_issue_http_request', autospec=True)
    def test_can_reach_metadata_server_with_error_response(self, mock_meta_req):
        """Test can_reach_metadata_server returns Falise with an
        invalid response.

        Setup:
            * Have httplib raise socket.error.

        Expected results:
            * A False result.
        """
        mock_meta_req.side_effect = _MockMetadataServerHttpError('Unreachable')
        actual_response = metadata_server.can_reach_metadata_server()
        self.assertFalse(actual_response)

    @mock.patch.object(metadata_server, '_issue_http_request', autospec=True)
    def test_get_value_for_attribute_with_exception(self, mock_meta_req):
        """Test get_value_for_attribute returns correctly.

        Setup:
            * Have _issue_http_request raise errors.MetadataServerHttpError

        Expected results:
            * A matching string.
        """
        mock_meta_req.side_effect = _MockMetadataServerHttpError('Unreachable')
        actual_response = metadata_server.get_value_for_attribute('')
        self.assertIsNone(actual_response)

    @mock.patch.object(metadata_server, '_issue_http_request', autospec=True)
    def test_get_value_for_attribute_with_a_present_attribute(self, mock_meta_req):
        """Test get_value_for_attribute returns correctly.

        Setup:
            * Mock out a httplib.HTTPResponse .
            * Return that from _issue_http_request.

        Expected results:
            * A matching string.
        """
        mock_response = 'expected_response'

        with mock.patch('httplib.HTTPResponse',
                        mock.mock_open(read_data=mock_response)) as mock_http_resp:
            mock_http_resp.return_value.status = httplib.OK
            mock_meta_req.side_effect = mock_http_resp

            actual_response = metadata_server.get_value_for_attribute('')

        self.assertEqual(actual_response, mock_response)


if __name__ == '__main__':
    unittest.main()
