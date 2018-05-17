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

"""Tests for install/gcp/installer/util/gcloud.py."""

import json
import sys
import unittest
from StringIO import StringIO
from contextlib import contextmanager

import mock
from install.gcp.installer.util import gcloud

from install.gcp.installer.util import utils
from tests.unittest_utils import ForsetiTestCase

FAKE_PROJECT = 'fake-project'
FAKE_ACCOUNT = 'fake-account@localhost.domain'

FAKE_GCLOUD_INFO = {
    'config': {
        'project': FAKE_PROJECT,
        'account': FAKE_ACCOUNT,
        'properties': {
        }
    }
}

FAKE_GCLOUD_INFO_CLOUDSHELL = {
    'config': {
        'project': FAKE_PROJECT,
        'account': FAKE_ACCOUNT,
        'properties': {
            'metrics': {
                'environment': 'devshell'
            }
        }
    }
}

FAKE_IAM_POLICY = {
    'bindings': [
        {'members': [
            'user:root@localhost.domain',
            'group:security-group@localhost.domain',
         ],
         'role': 'roles/fakeAdminRole'
        },
        {'members': [
            'user:user1@localhost.domain',
            'user:{}'.format(FAKE_ACCOUNT),
         ],
         'role': 'roles/fakeViewerRole'
        },
        {'members': [
            'user:{}'.format(FAKE_ACCOUNT),
         ],
         'role': 'roles/fakeEditorRole'
        },
    ]
}

GCLOUD_MIN_VERSION = (163, 0, 0)


# Thank you https://stackoverflow.com/questions/4219717/how-to-assert-output-with-nosetest-unittest-in-python/17981937#17981937
@contextmanager
def captured_output():
    new_out, new_err = StringIO(), StringIO()
    old_out, old_err = sys.stdout, sys.stderr
    try:
        sys.stdout, sys.stderr = new_out, new_err
        yield sys.stdout, sys.stderr
    finally:
        sys.stdout, sys.stderr = old_out, old_err


class GcloudTest(ForsetiTestCase):
    """Test the install_forseti."""

    def setUp(self):
        """Setup."""
        utils.run_command = mock.MagicMock()
        self.gcloud_min_ver_formatted = '.'.join([str(d) for d in GCLOUD_MIN_VERSION])

    @mock.patch('install.gcp.installer.util.gcloud.constants.GCLOUD_MIN_VERSION', GCLOUD_MIN_VERSION)
    @mock.patch('install.gcp.installer.util.gcloud.utils.run_command')
    def test_check_proper_gcloud(self, test_patch):
        """Test check_proper_gcloud() works with proper version/alpha."""
        test_patch.return_value = (
            0,
            'Google Cloud SDK %s\nalpha 12345\netc' % self.gcloud_min_ver_formatted,
            None
        )
        output_head = 'Current gcloud version'
        with captured_output() as (out, err):
            gcloud.check_proper_gcloud()
            output = out.getvalue()[:len(output_head)]
            self.assertEqual(output_head, output)

    @mock.patch('install.gcp.installer.util.gcloud.utils.run_command')
    def test_check_proper_gcloud_failed_command(self, test_patch):
        """Test check_proper_gcloud() exits when command fails."""
        test_patch.return_value = (
            1,
            'Google Cloud SDK %s\nalpha 12345\netc' % self.gcloud_min_ver_formatted,
            None
        )
        output_head = 'Error'
        with self.assertRaises(SystemExit):
            with captured_output() as (out, err):
                gcloud.check_proper_gcloud()
                output = out.getvalue()[:len(output_head)]
                self.assertEqual(output_head, output)

    @mock.patch('install.gcp.installer.util.gcloud.utils.run_command')
    def test_check_proper_gcloud_low_version(self, test_patch):
        """Test check_proper_gcloud() exits with low gcloud version."""
        test_patch.return_value = (
            0,
            'Google Cloud SDK 162.9.9\nalpha 12345\netc',
            None
        )
        output_head = ('Current gcloud version: %s\n'
                       'Has alpha components? True'
                       'You need' % self.gcloud_min_ver_formatted)
        with self.assertRaises(SystemExit):
            with captured_output() as (out, err):
                gcloud.check_proper_gcloud()
                output = out.getvalue()[:len(output_head)]

    @mock.patch('install.gcp.installer.util.gcloud.utils.run_command')
    def test_check_proper_gcloud_no_alpha(self, test_patch):
        """Test check_proper_gcloud() exits with no alpha components."""
        test_patch.return_value = (
            0,
            'Google Cloud SDK %s\netc' % self.gcloud_min_ver_formatted,
            None
        )
        output_head = ('Current gcloud version: %s\n'
                       'Has alpha components? False\n'
                       'You need' % self.gcloud_min_ver_formatted)
        with self.assertRaises(SystemExit):
            with captured_output() as (out, err):
                gcloud.check_proper_gcloud()
                output = out.getvalue()[:len(output_head)]
                self.assertEqual(output_head, output)

    @mock.patch('install.gcp.installer.util.gcloud.utils.run_command')
    def test_gcloud_info_works_nocloudshell(self, test_patch):
        """Test gcloud_info()."""
        test_patch.return_value = (
            0,
            json.dumps(FAKE_GCLOUD_INFO),
            None
        )
        with captured_output() as (out, err):
            gcloud.get_gcloud_info()
            output = out.getvalue().strip()
            self.assertEqual('Read gcloud info: Success', output)

    @mock.patch('install.gcp.installer.util.gcloud.utils.run_command')
    def test_gcloud_info_cmd_fails(self, test_patch):
        """Test gcloud_info() exits when command fails."""
        test_patch.return_value = (
            1,
            None,
            'Error output'
        )
        with self.assertRaises(SystemExit):
            with captured_output():
                gcloud.check_proper_gcloud()

    @mock.patch('install.gcp.installer.util.gcloud.utils.run_command')
    def test_gcloud_info_json_fails(self, test_patch):
        """Test gcloud_info() exits when json output fails."""
        test_patch.return_value = (
            0,
            'invalid json',
            None,
        )
        with self.assertRaises(SystemExit):
            with captured_output():
                gcloud.get_gcloud_info()

    @mock.patch('install.gcp.installer.util.gcloud.check_proper_gcloud')
    def test_check_cloudshell_no_flag_no_cloudshell(self, test_patch):
        """Test check_cloudshell() when no cloudshell and no flag to bypass."""
        test_patch.return_value = {}
        force_no_cloudshell = False
        is_dev_shell = False
        with self.assertRaises(SystemExit):
            with captured_output():
                gcloud.verify_gcloud_information(
                    'id', 'user', force_no_cloudshell, is_dev_shell)

    @mock.patch('install.gcp.installer.util.gcloud.utils.run_command')
    def test_lookup_organization(self, test_patch):
        """Test lookup_organization().

        Find organization from a project nested inside 3 folders.
        """
        project_desc = json.dumps({
            'name': 'project-1',
            'parent': {
                'id': '12345',
                'type': 'folder'
            },
        })
        folder_12345_desc = json.dumps({
            'name': 'folders/12345',
            'parent': 'folders/23456'
        })
        folder_23456_desc = json.dumps({
            'name': 'folders/23456',
            'parent': 'folders/34567'
        })
        folder_34567_desc = json.dumps({
            'name': 'folders/34567',
            'parent': 'organizations/1111122222'
        })

        test_patch.side_effect = [
            [0, project_desc, None],
            [0, folder_12345_desc, None],
            [0, folder_23456_desc, None],
            [0, folder_34567_desc, None],
        ]

        output_head = 'Organization id'
        with captured_output() as (out, err):
            gcloud.lookup_organization(FAKE_PROJECT)
            # collect all the output, the last line (excluding blank line)
            # should be 'Organization id: ...'
            all_output = [s for s in out.getvalue().split('\n') if len(s)]
            output = all_output[-1][:len(output_head)]
            self.assertEqual(output_head, output)

    @mock.patch('install.gcp.installer.util.gcloud.utils.run_command')
    def test_choose_organization_no_org(self, test_patch):
        """Test choose_organization()."""
        # No orgs
        test_patch.return_value = (0, '{}', None)
        with captured_output() as (out, err):
            target_id = gcloud.choose_organization()
            self.assertEqual(None, target_id)

    @mock.patch('install.gcp.installer.util.gcloud.utils.run_command')
    @mock.patch('__builtin__.raw_input')
    def test_choose_organization_has_org(self, mock_rawinput, test_patch):
        """Test choose_organization()."""
        mock_rawinput.side_effect = ['123']
        # Has orgs
        test_patch.return_value = (
            0, '[{"name": "organizations/123", "displayName": "fake org"}]', None)
        with captured_output() as (out, err):
            target_id = gcloud.choose_organization()
            self.assertEqual('123', target_id)

    @mock.patch('__builtin__.raw_input')
    def test_choose_folder(self, mock_rawinput):
        """Test choose_folder()."""
        mock_rawinput.side_effect = ['abc', '123']
        # Has orgs
        with captured_output() as (out, err):
            target_id = gcloud.choose_folder(FAKE_PROJECT)
            self.assertEqual('123', target_id)

    @mock.patch('__builtin__.raw_input')
    def test_choose_project(self, mock_rawinput):
        """Test choose_project()."""
        mock_rawinput.side_effect = ['abc']
        # Has orgs
        with captured_output() as (out, err):
            target_id = gcloud.choose_project()
            self.assertEqual('abc', target_id)

if __name__ == '__main__':
    unittest.main()
