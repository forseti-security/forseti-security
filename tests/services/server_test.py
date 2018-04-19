# Copyright 2018 The Forseti Security Authors. All rights reserved.
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
"""Unit Tests: Forseti Server."""

import unittest
import mock
from tests.unittest_utils import ForsetiTestCase
from google.cloud.forseti.services import server
import pdb



class NameSpace(object):
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)


class ServerTest(ForsetiTestCase):
    """Test Forseti Server."""

    @mock.patch('google.cloud.forseti.services.server.argparse', autospec=True)
    def test_services_not_specified(self, mock_argparse):
        """Test main() with no service specified."""
        expected_exit_code = 1
        mock_arg_parser = mock.MagicMock()
        mock_argparse.ArgumentParser.return_value = mock_arg_parser
        mock_arg_parser.parse_args.return_value = NameSpace(
            endpoint='[::]:50051',
            services=None,
            forseti_db=None,
            config_file_path=None,
            log_level='info',
            enable_console_log=False)

        with self.assertRaises(SystemExit) as e:
            server.main()
        self.assertEquals(expected_exit_code, e.exception.code)

    @mock.patch('google.cloud.forseti.services.server.argparse', autospec=True)
    def test_config_file_path_not_specified(self, mock_argparse):
        """Test main() with no config_file_path specified."""
        expected_exit_code = 2
        mock_arg_parser = mock.MagicMock()
        mock_argparse.ArgumentParser.return_value = mock_arg_parser
        mock_arg_parser.parse_args.return_value = NameSpace(
            endpoint='[::]:50051',
            services=['scanner'],
            forseti_db=None,
            config_file_path=None,
            log_level='info',
            enable_console_log=False)

        with self.assertRaises(SystemExit) as e:
            server.main()
        self.assertEquals(expected_exit_code, e.exception.code)

    @mock.patch('google.cloud.forseti.services.server.argparse', autospec=True)
    def test_config_file_path_non_readable_file(self, mock_argparse):
        """Test main() with non-readable config file."""
        expected_exit_code = 3
        mock_arg_parser = mock.MagicMock()
        mock_argparse.ArgumentParser.return_value = mock_arg_parser
        mock_arg_parser.parse_args.return_value = NameSpace(
            endpoint='[::]:50051',
            services=['scanner'],
            forseti_db=None,
            config_file_path='/this/does/not/exist',
            log_level='info',
            enable_console_log=False)

        with self.assertRaises(SystemExit) as e:
            server.main()
        self.assertEquals(expected_exit_code, e.exception.code)

    @mock.patch('google.cloud.forseti.services.server.argparse', autospec=True)
    def test_config_file_path_non_existent_file(self, mock_argparse):
        """Test main() with non-existent config file."""
        expected_exit_code = 4
        mock_arg_parser = mock.MagicMock()
        mock_argparse.ArgumentParser.return_value = mock_arg_parser
        mock_arg_parser.parse_args.return_value = NameSpace(
            endpoint='[::]:50051',
            services=['scanner'],
            forseti_db=None,
            config_file_path='/what/ever',
            log_level='info',
            enable_console_log=False)

        with mock.patch.object(server.os.path, "isfile") as mock_isfile:
            mock_isfile.return_value = True
            with mock.patch.object(server.os, "access") as mock_access:
                mock_access.return_value = False
                with self.assertRaises(SystemExit) as e:
                    server.main()
        self.assertEquals(expected_exit_code, e.exception.code)

    @mock.patch('google.cloud.forseti.services.server.argparse', autospec=True)
    def test_forseti_db_not_set(self, mock_argparse):
        """Test main() with forseti_db not set."""
        expected_exit_code = 5
        mock_arg_parser = mock.MagicMock()
        mock_argparse.ArgumentParser.return_value = mock_arg_parser
        mock_arg_parser.parse_args.return_value = NameSpace(
            endpoint='[::]:50051',
            services=['scanner'],
            forseti_db=None,
            config_file_path='/what/ever',
            log_level='info',
            enable_console_log=False)

        with mock.patch.object(server.os.path, "isfile") as mock_isfile:
            mock_isfile.return_value = True
            with mock.patch.object(server.os, "access") as mock_access:
                mock_access.return_value = True
                with self.assertRaises(SystemExit) as e:
                    server.main()
        self.assertEquals(expected_exit_code, e.exception.code)


if __name__ == '__main__':
    unittest.main()
