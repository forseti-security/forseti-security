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

import mock
import argparse
import os
import unittest

from tests.unittest_utils import ForsetiTestCase
from google.cloud.forseti.services import server


class NameSpace(object):
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)


class ServerTest(ForsetiTestCase):
    """Test Forseti Server."""

    TEST_RESOURCE_DIR_PATH = os.path.join(
        os.path.dirname(__file__), 'test_data')

    @mock.patch('google.cloud.forseti.services.base.config.ModelManager',
                mock.MagicMock())
    @mock.patch('google.cloud.forseti.services.base.config.create_engine')
    def test_server_config_update_bad_default_path(self, test_patch):
        test_patch.return_value = None

        config_file_path = ''
        db_conn_str = ''
        endpoint = ''

        config = server.ServiceConfig(config_file_path, db_conn_str, endpoint)

        is_success, err_msg = config.update_configuration()

        has_err_msg = len(err_msg) > 0

        self.assertFalse(is_success)

        self.assertTrue(has_err_msg)

    @mock.patch('google.cloud.forseti.services.base.config.ModelManager',
                mock.MagicMock())
    @mock.patch('google.cloud.forseti.services.base.config.create_engine')
    def test_server_config_update_good_default_bad_update_path(self, test_patch):
        test_patch.return_value = None

        config_file_path = os.path.join(self.TEST_RESOURCE_DIR_PATH,
                                        'forseti_conf_server.yaml')
        db_conn_str = ''
        endpoint = ''
        config = server.ServiceConfig(config_file_path, db_conn_str, endpoint)

        is_success, err_msg = config.update_configuration()

        has_err_msg = len(err_msg) > 0

        self.assertTrue(is_success)

        self.assertFalse(has_err_msg)

        # Examine the contents in scanner config.

        for scanner in config.get_scanner_config().get('scanners'):
            # All the scanners are set to true in the default config file.
            self.assertTrue(scanner.get('enabled'))

        # Test update config with bad file path.

        is_success, err_msg = config.update_configuration(
            'this_is_a_bad_path.xyz')

        has_err_msg = len(err_msg) > 0

        self.assertFalse(is_success)

        self.assertTrue(has_err_msg)

        # Make sure if the new path is bad, we still keep the good changes
        # from the default path, we can verify by examining the contents in
        # the scanner config and see if it's the same as above.

        for scanner in config.get_scanner_config().get('scanners'):
            # All the scanners are set to true in the default config file.
            self.assertTrue(scanner.get('enabled'))

    @mock.patch('google.cloud.forseti.services.base.config.ModelManager',
                mock.MagicMock())
    @mock.patch('google.cloud.forseti.services.base.config.create_engine')
    def test_server_config_update_good_default_and_update_path(self, test_patch):
        test_patch.return_value = None

        config_file_path = os.path.join(self.TEST_RESOURCE_DIR_PATH,
                                        'forseti_conf_server.yaml')
        db_conn_str = ''
        endpoint = ''
        config = server.ServiceConfig(config_file_path, db_conn_str, endpoint)

        _, _ = config.update_configuration()

        new_config_file_path = os.path.join(self.TEST_RESOURCE_DIR_PATH,
                                            'forseti_conf_server_new.yaml')

        is_success, err_msg = config.update_configuration(new_config_file_path)

        has_err_msg = len(err_msg) > 0

        self.assertTrue(is_success)

        self.assertFalse(has_err_msg)

        # Examine the contents in scanner config.

        for scanner in config.get_scanner_config().get('scanners'):
            # All the scanners are set to false in the new config file.
            self.assertFalse(scanner.get('enabled'))

        # Test update again with default path will replace the changes.

        is_success, err_msg = config.update_configuration()

        has_err_msg = len(err_msg) > 0

        self.assertTrue(is_success)

        self.assertFalse(has_err_msg)

        # Examine the contents in scanner config.

        for scanner in config.get_scanner_config().get('scanners'):
            # All the scanners are set to true in the default config file.
            self.assertTrue(scanner.get('enabled'))

    @mock.patch.object(argparse.ArgumentParser, 'parse_args')
    @mock.patch.object(argparse.ArgumentParser, 'print_usage')
    @mock.patch('sys.stderr', autospec=True)
    def test_services_not_specified(self, mock_sys_error, mock_print_usage, mock_argparse):
        """Test main() with no service specified."""
        expected_exit_code = 1
        mock_argparse.return_value = NameSpace(
            endpoint='[::]:50051',
            services=None,
            forseti_db=None,
            config_file_path=None,
            log_level='info',
            enable_console_log=False)
        mock_print_usage.return_value = None

        with self.assertRaises(SystemExit) as e:
            server.main()
        self.assertEquals(expected_exit_code, e.exception.code)
        self.assertTrue(mock_sys_error.write.called)

    @mock.patch.object(argparse.ArgumentParser, 'parse_args')
    @mock.patch.object(argparse.ArgumentParser, 'print_usage')
    @mock.patch('sys.stderr', autospec=True)
    def test_config_file_path_not_specified(self, mock_sys_error, mock_print_usage, mock_argparse):
        """Test main() with no config_file_path specified."""
        expected_exit_code = 2
        mock_argparse.return_value = NameSpace(
            endpoint='[::]:50051',
            services=['scanner'],
            forseti_db=None,
            config_file_path=None,
            log_level='info',
            enable_console_log=False)
        mock_print_usage.return_value = None

        with self.assertRaises(SystemExit) as e:
            server.main()
        self.assertEquals(expected_exit_code, e.exception.code)
        self.assertTrue(mock_sys_error.write.called)

    @mock.patch.object(argparse.ArgumentParser, 'parse_args')
    @mock.patch.object(argparse.ArgumentParser, 'print_usage')
    @mock.patch('sys.stderr', autospec=True)
    def test_config_file_path_non_readable_file(self, mock_sys_error, mock_print_usage, mock_argparse):
        """Test main() with non-readable config file."""
        expected_exit_code = 3
        mock_argparse.return_value = NameSpace(
            endpoint='[::]:50051',
            services=['scanner'],
            forseti_db=None,
            config_file_path='/this/does/not/exist',
            log_level='info',
            enable_console_log=False)
        mock_print_usage.return_value = None

        with self.assertRaises(SystemExit) as e:
            server.main()
        self.assertEquals(expected_exit_code, e.exception.code)
        self.assertTrue(mock_sys_error.write.called)

    @mock.patch.object(argparse.ArgumentParser, 'parse_args')
    @mock.patch.object(argparse.ArgumentParser, 'print_usage')
    @mock.patch('sys.stderr', autospec=True)
    def test_config_file_path_non_existent_file(self, mock_sys_error, mock_print_usage, mock_argparse):
        """Test main() with non-existent config file."""
        expected_exit_code = 4
        mock_argparse.return_value = NameSpace(
            endpoint='[::]:50051',
            services=['scanner'],
            forseti_db=None,
            config_file_path='/what/ever',
            log_level='info',
            enable_console_log=False)
        mock_print_usage.return_value = None

        with mock.patch.object(server.os.path, "isfile") as mock_isfile:
            mock_isfile.return_value = True
            with mock.patch.object(server.os, "access") as mock_access:
                mock_access.return_value = False
                with self.assertRaises(SystemExit) as e:
                    server.main()
        self.assertEquals(expected_exit_code, e.exception.code)
        self.assertTrue(mock_sys_error.write.called)

    @mock.patch.object(argparse.ArgumentParser, 'parse_args')
    @mock.patch.object(argparse.ArgumentParser, 'print_usage')
    @mock.patch('sys.stderr', autospec=True)
    def test_forseti_db_not_set(self, mock_sys_error, mock_print_usage,  mock_argparse):
        """Test main() with forseti_db not set."""
        expected_exit_code = 5
        mock_argparse.return_value = NameSpace(
            endpoint='[::]:50051',
            services=['scanner'],
            forseti_db=None,
            config_file_path='/what/ever',
            log_level='info',
            enable_console_log=False)

        mock_print_usage.return_value = None

        with mock.patch.object(server.os.path, "isfile") as mock_isfile:
            mock_isfile.return_value = True
            with mock.patch.object(server.os, "access") as mock_access:
                mock_access.return_value = True
                with self.assertRaises(SystemExit) as e:
                    server.main()
        self.assertEquals(expected_exit_code, e.exception.code)
        self.assertTrue(mock_sys_error.write.called)


if __name__ == '__main__':
    unittest.main()
