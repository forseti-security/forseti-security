"""Tests for google3.experimental.users.ahoying.forseti.forseti-security.tests.services.config."""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import os
import unittest
import mock

from tests import unittest_utils
from google.cloud.forseti.services.base import config

TEST_RESOURCE_DIR_PATH = os.path.join(os.path.dirname(__file__), 'test_data')


@mock.patch.object(config, 'ModelManager', auto_spec=True)
@mock.patch.object(config, 'create_engine', return_value='')
class ConfigTest(unittest_utils.ForsetiTestCase):

    def test_server_config_update_bad_default_path(self, mock_engine, mock_mm):
        config_file_path = ''
        db_conn_str = ''
        endpoint = ''

        service_config = config.ServiceConfig(config_file_path,
                                              db_conn_str,
                                              endpoint)

        is_success, err_msg = service_config.update_configuration()

        has_err_msg = len(err_msg) > 0

        self.assertFalse(is_success)

        self.assertTrue(has_err_msg)

    def test_server_config_update_good_default_bad_update_path(self,
                                                               mock_engine,
                                                               mock_mm):
        config_file_path = os.path.join(TEST_RESOURCE_DIR_PATH,
                                        'forseti_conf_server.yaml')
        db_conn_str = ''
        endpoint = ''
        service_config = config.ServiceConfig(config_file_path,
                                              db_conn_str,
                                              endpoint)

        is_success, err_msg = service_config.update_configuration()

        has_err_msg = len(err_msg) > 0

        self.assertTrue(is_success)

        self.assertFalse(has_err_msg)

        # Examine the contents in scanner config.

        for scanner in service_config.get_scanner_config().get('scanners'):
            # All the scanners are set to true in the default config file.
            self.assertTrue(scanner.get('enabled'))

        # Test update config with bad file path.

        is_success, err_msg = service_config.update_configuration(
            'this_is_a_bad_path.xyz')

        has_err_msg = len(err_msg) > 0

        self.assertFalse(is_success)

        self.assertTrue(has_err_msg)

        # Make sure if the new path is bad, we still keep the good changes
        # from the default path, we can verify by examining the contents in
        # the scanner config and see if it's the same as above.

        for scanner in service_config.get_scanner_config().get('scanners'):
            # All the scanners are set to true in the default config file.
            self.assertTrue(scanner.get('enabled'))

    def test_server_config_update_good_default_and_update_path(self,
                                                               mock_engine,
                                                               mock_mm):
        config_file_path = os.path.join(TEST_RESOURCE_DIR_PATH,
                                        'forseti_conf_server.yaml')
        db_conn_str = ''
        endpoint = ''
        service_config = config.ServiceConfig(config_file_path,
                                              db_conn_str,
                                              endpoint)

        _, _ = service_config.update_configuration()

        new_config_file_path = os.path.join(TEST_RESOURCE_DIR_PATH,
                                            'forseti_conf_server_new.yaml')

        is_success, err_msg = service_config.update_configuration(
            new_config_file_path)

        has_err_msg = len(err_msg) > 0

        self.assertTrue(is_success)
        self.assertFalse(has_err_msg)

        # Examine the contents in scanner config.

        for scanner in service_config.get_scanner_config().get('scanners'):
            # All the scanners are set to false in the new config file.
            self.assertFalse(scanner.get('enabled'))

        # Test update again with default path will replace the changes.

        is_success, err_msg = service_config.update_configuration()

        has_err_msg = len(err_msg) > 0

        self.assertTrue(is_success)
        self.assertFalse(has_err_msg)

        # Examine the contents in scanner config.

        for scanner in service_config.get_scanner_config().get('scanners'):
            # All the scanners are set to true in the default config file.
            self.assertTrue(scanner.get('enabled'))

    def test_server_config_composite_root(self, mock_engine, mock_mm):
        config_file_path = os.path.join(
            TEST_RESOURCE_DIR_PATH, 'forseti_conf_server_composite_root.yaml')
        db_conn_str = ''
        endpoint = ''

        service_config = config.ServiceConfig(config_file_path,
                                              db_conn_str,
                                              endpoint)

        is_success, err_msg = service_config.update_configuration()

        has_err_msg = len(err_msg) > 0

        self.assertTrue(is_success)
        self.assertFalse(has_err_msg)

        inventory_config = service_config.get_inventory_config()
        self.assertTrue(inventory_config.use_composite_root())

        expected_composite_root_resources = 4
        self.assertEqual(expected_composite_root_resources,
                         len(inventory_config.get_composite_root_resources()))

    def test_server_config_composite_and_root(self, mock_engine, mock_mm):
        """Both root_resource_id and composite_root_resources is error."""
        config_file_path = os.path.join(
            TEST_RESOURCE_DIR_PATH,
            'forseti_conf_server_composite_and_root.yaml')
        db_conn_str = ''
        endpoint = ''

        service_config = config.ServiceConfig(config_file_path,
                                              db_conn_str,
                                              endpoint)

        is_success, err_msg = service_config.update_configuration()

        has_err_msg = len(err_msg) > 0

        self.assertFalse(is_success)
        self.assertTrue(has_err_msg)

        self.assertIn('Both root_resource_id and composite_root_resources',
                      err_msg)

    def test_server_config_neither_composite_nor_root(self, mock_engine, mock_mm):
        """Neither root_resource_id and composite_root_resources is error."""
        config_file_path = os.path.join(
            TEST_RESOURCE_DIR_PATH,
            'forseti_conf_server_neither_composite_nor_root.yaml')
        db_conn_str = ''
        endpoint = ''

        service_config = config.ServiceConfig(config_file_path,
                                              db_conn_str,
                                              endpoint)

        is_success, err_msg = service_config.update_configuration()

        has_err_msg = len(err_msg) > 0

        self.assertFalse(is_success)
        self.assertTrue(has_err_msg)

        self.assertIn('Neither root_resource_id nor composite_root_resources',
                      err_msg)

if __name__ == '__main__':
    unittest.main()
