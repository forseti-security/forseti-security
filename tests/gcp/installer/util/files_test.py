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

"""Tests for install/gcp/installer/util/files.py."""

import unittest
import tempfile
import filecmp
import os

import install.gcp.installer.util.files as files

from tests.unittest_utils import ForsetiTestCase

TEST_RESOURCE_DIR_PATH = os.path.join(
    os.path.dirname(__file__), 'test_data')
TEST_TMP_DIR_PREFIX = 'forseti-test-'


class FilesTest(ForsetiTestCase):

    def test_generate_file_from_template_forseti_conf_client(self):
        """Test generation of forseti_conf client template"""
        # input template
        tpl_path = os.path.join(TEST_RESOURCE_DIR_PATH,
                                'forseti_conf_client.yaml.in')

        # output path
        tempdir = tempfile.mkdtemp(prefix=TEST_TMP_DIR_PREFIX)
        gen_file_path = os.path.join(tempdir, 'test_file_conf_client.yaml')

        # values for the template
        vals = {
            'SERVER_IP': '192.168.0.1'
        }

        # create file
        files.generate_file_from_template(tpl_path, gen_file_path, vals)

        # verify the content of the generated file is as expected
        expected_file_content = os.path.join(TEST_RESOURCE_DIR_PATH,
                                             'expected_forseti_conf_client.yaml')
        is_same = filecmp.cmp(gen_file_path, expected_file_content)
        self.assertTrue(is_same)

        # delete generated file & directory
        os.unlink(gen_file_path)
        os.rmdir(tempdir)
        self.assertFalse(os.path.exists(tempdir))

    def test_generate_file_from_template_forseti_conf_server(self):
        """Test generation of forseti_conf server template"""
        # input template
        tpl_path = os.path.join(TEST_RESOURCE_DIR_PATH,
                                'forseti_conf_server.yaml.in')

        # output path
        tempdir = tempfile.mkdtemp(prefix=TEST_TMP_DIR_PREFIX)
        gen_file_path = os.path.join(tempdir, 'test_file_conf_server.yaml')

        # values for the template
        vals = {
            'DOMAIN_SUPER_ADMIN_EMAIL': 'test@forseti_test_gmail.com',
            'EMAIL_RECIPIENT': 'rec@forseti_test_gmail.com',
            'EMAIL_SENDER': 'send@forseti_test_gmail.com',
            'SENDGRID_API_KEY': 'TESTING_API_KEY',
            'SCANNER_BUCKET': 'TESTING_BUCKET',
            'ENABLE_GROUP_SCANNER': 'true'
        }

        # create file
        files.generate_file_from_template(tpl_path, gen_file_path, vals)

        # verify the content of the generated file is as expected
        expected_file_content = os.path.join(TEST_RESOURCE_DIR_PATH,
                                             'expected_forseti_conf_server.yaml')
        is_same = filecmp.cmp(gen_file_path, expected_file_content)
        self.assertTrue(is_same)

        # delete generated file & directory
        os.unlink(gen_file_path)
        os.rmdir(tempdir)
        self.assertFalse(os.path.exists(tempdir))

    def test_generate_file_from_template_dpl_tpl_client(self):
        """Test generation of deployment template"""
        # input template
        tpl_path = os.path.join(TEST_RESOURCE_DIR_PATH,
                                'deploy-forseti-client.yaml.in')

        # output path
        tempdir = tempfile.mkdtemp(prefix=TEST_TMP_DIR_PREFIX)
        gen_file_path = os.path.join(tempdir, 'test_file_dpl_client.yaml')

        # values for the template
        vals = {
            'SCANNER_BUCKET': 'TEST_BUCKET',
            'BUCKET_LOCATION': 'BUCKET_LOC',
            'SERVICE_ACCOUNT_GCP': 'gcp@test_forseti_gmail.com',
            'BRANCH_OR_RELEASE': 'branch-name: "Master"',
            'FORSETI_SERVER_ZONE': 'FORSETI_SERVER_ZONE'
        }

        # create file
        files.generate_file_from_template(tpl_path, gen_file_path, vals)

        # verify the content of the generated file is as expected
        expected_file_content = os.path.join(TEST_RESOURCE_DIR_PATH,
                                             'expected-deploy-forseti-client.yaml')
        is_same = filecmp.cmp(gen_file_path, expected_file_content)
        self.assertTrue(is_same)

        # delete generated file & directory
        os.unlink(gen_file_path)
        os.rmdir(tempdir)
        self.assertFalse(os.path.exists(tempdir))

    def test_generate_file_from_template_dpl_tpl_server(self):
        """Test generation of deployment template"""
        # input template
        tpl_path = os.path.join(TEST_RESOURCE_DIR_PATH,
                                'deploy-forseti-server.yaml.in')

        # output path
        tempdir = tempfile.mkdtemp(prefix=TEST_TMP_DIR_PREFIX)
        gen_file_path = os.path.join(tempdir, 'test_file_dpl_server.yaml')

        # values for the template
        vals = {
            'CLOUDSQL_REGION': 'TEST_CLOUDSQL_REGION',
            'CLOUDSQL_INSTANCE_NAME': 'TEST_CLOUDSQL_INSTANCE_NAME',
            'SCANNER_BUCKET': 'TEST_BUCKET',
            'BUCKET_LOCATION': 'BUCKET_LOC',
            'SERVICE_ACCOUNT_GCP': 'gcp@test_forseti_gmail.com',
            'SERVICE_ACCOUNT_GSUITE': 'gsuite@test_forseti_gmail.com',
            'BRANCH_OR_RELEASE': 'branch-name: "master"',
            'GSUITE_ADMIN_EMAIL': 'gsuiteadmin@test_forseti_gmail.com',
            'ROOT_RESOURCE_ID': 'TEST_ROOT_ID',
            'rand_minute': '5'
        }

        # create file
        files.generate_file_from_template(tpl_path, gen_file_path, vals)

        # verify the content of the generated file is as expected
        expected_file_content = os.path.join(TEST_RESOURCE_DIR_PATH,
                                             'expected-deploy-forseti-server.yaml')
        is_same = filecmp.cmp(gen_file_path, expected_file_content)
        self.assertTrue(is_same)

        # delete generated file & directory
        os.unlink(gen_file_path)
        os.rmdir(tempdir)
        self.assertFalse(os.path.exists(tempdir))


if __name__ == '__main__':
    unittest.main()
