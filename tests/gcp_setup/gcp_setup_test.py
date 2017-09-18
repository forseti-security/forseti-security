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

"""Tests the gcp_setup."""

import json
import mock
import sys
import unittest

from contextlib import contextmanager
from StringIO import StringIO

from tests.unittest_utils import ForsetiTestCase
from scripts.gcp_setup.environment import gcloud_env

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

class GcloudEnvTest(ForsetiTestCase):
    """Test the gcp_setup."""

    def setUp(self):
        self.gcp_setup = gcloud_env.ForsetiGcpSetup()
        self.gcp_setup._run_command = mock.MagicMock()

    def test_check_proper_gcloud(self):
        """Test check_proper_gcloud() works with proper version/alpha."""
        self.gcp_setup._run_command.return_value = [
            0,
            'Google Cloud SDK 163.0.0\nalpha 12345\netc',
            None
        ]
        output_head = 'Current gcloud version'
        with captured_output() as (out, err):
            self.gcp_setup.check_proper_gcloud()
            output = out.getvalue()[:len(output_head)]
            self.assertEqual(output_head, output)

    def test_check_proper_gcloud_failed_command(self):
        """Test check_proper_gcloud() exits when command fails."""
        self.gcp_setup._run_command.return_value = [
            1,
            'Google Cloud SDK 163.0.0\nalpha 12345\netc',
            None
        ]
        output_head = 'Error'
        with self.assertRaises(SystemExit):
            with captured_output() as (out, err):
                self.gcp_setup.check_proper_gcloud()
                output = out.getvalue()[:len(output_head)]
                self.assertEqual(output_head, output)

    def test_check_proper_gcloud_low_version(self):
        """Test check_proper_gcloud() exits with low gcloud version."""
        self.gcp_setup._run_command.return_value = [
            0,
            'Google Cloud SDK 162.9.9\nalpha 12345\netc',
            None
        ]
        output_head = ('Current gcloud version: 123.0.0\n'
                       'Has alpha components? True'
                       'You need')
        with self.assertRaises(SystemExit):
            with captured_output() as (out, err):
                self.gcp_setup.check_proper_gcloud()
                output = out.getvalue()[:len(output_head)]
                self.assertEqual(output_head, output)

    def test_check_proper_gcloud_no_alpha(self):
        """Test check_proper_gcloud() exits with no alpha components."""
        self.gcp_setup._run_command.return_value = [
            0,
            'Google Cloud SDK 163.0.0\netc',
            None
        ]
        output_head = ('Current gcloud version: 163.0.0\n'
                       'Has alpha components? False\n'
                       'You need')
        with self.assertRaises(SystemExit):
            with captured_output() as (out, err):
                self.gcp_setup.check_proper_gcloud()
                output = out.getvalue()[:len(output_head)]
                self.assertEqual(output_head, output)

    def test_gcloud_info_works_nocloudshell(self):
        """Test gcloud_info()."""
        self.gcp_setup._run_command.return_value = [
            0,
            json.dumps(FAKE_GCLOUD_INFO),
            None
        ]
        with captured_output() as (out, err):
            self.gcp_setup.gcloud_info()
            output = out.getvalue().strip()
            self.assertEqual('Got gcloud info', output)

    def test_gcloud_info_cmd_fails(self):
        """Test gcloud_info() exits when command fails."""
        self.gcp_setup._run_command.return_value = [
            1,
            None,
            'Error output'
        ]
        with self.assertRaises(SystemExit):
            with captured_output():
                self.gcp_setup.check_proper_gcloud()

    def test_gcloud_info_json_fails(self):
        """Test gcloud_info() exits when json output fails."""
        self.gcp_setup._run_command.return_value = [
            0,
            'invalid json',
            None,
        ]
        with self.assertRaises(SystemExit):
            with captured_output():
                self.gcp_setup.check_proper_gcloud()

    def test_check_cloudshell_no_flag_no_cloudshell(self):
        """Test check_cloudshell() when no cloudshell and no flag to bypass."""
        with self.assertRaises(SystemExit):
            with captured_output():
                self.gcp_setup.check_cloudshell()

    def test_check_cloudshell_with_flag_no_cloudshell(self):
        """Test check_cloudshell() when no cloudshell and flag to bypass."""
        output_head = 'Bypass Cloud Shell'
        self.gcp_setup.force_no_cloudshell = True
        with captured_output() as (out, err):
            self.gcp_setup.check_cloudshell()
            output = out.getvalue().strip()[:len(output_head)]
            self.assertEqual(output_head, output)

    def test_check_cloudshell_no_flag_is_cloudshell(self):
        """Test check_cloudshell() when using cloudshell, no flag to bypass."""
        output_head = 'Using Cloud Shell'
        self.gcp_setup.is_devshell = True
        with captured_output() as (out, err):
            self.gcp_setup.check_cloudshell()
            output = out.getvalue().strip()[:len(output_head)]
            self.assertEqual(output_head, output)

    def test_check_cloudshell_has_flag_is_cloudshell(self):
        """Test check_cloudshell() when using cloudshell and flag to bypass."""
        output_head = 'Bypass Cloud Shell'
        self.gcp_setup.force_no_cloudshell = True
        self.gcp_setup.is_devshell = True
        with captured_output() as (out, err):
            self.gcp_setup.check_cloudshell()
            output = out.getvalue().strip()[:len(output_head)]
            self.assertEqual(output_head, output)

    def test_get_authed_user(self):
        """Test get_authed_user()."""
        with self.assertRaises(SystemExit):
            with captured_output():
                self.gcp_setup.get_authed_user()

        self.gcp_setup.authed_user = FAKE_ACCOUNT
        output_head = 'You are'
        with captured_output() as (out, err):
            self.gcp_setup.get_authed_user()
            output = out.getvalue()[:len(output_head)]
            self.assertEqual(output_head, output)

    def test_get_project(self):
        """Test get_project()."""
        with self.assertRaises(SystemExit):
            with captured_output():
                self.gcp_setup.get_project()

        self.gcp_setup.project_id = FAKE_PROJECT
        output_head = 'Project id'
        with captured_output() as (out, err):
            self.gcp_setup.get_project()
            output = out.getvalue()[:len(output_head)]
            self.assertEqual(output_head, output)

    def test_get_organization(self):
        """Test get_organization().

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
        self.gcp_setup.project_id = FAKE_PROJECT
        self.gcp_setup._run_command.side_effect = [
            [0, project_desc, None],
            [0, folder_12345_desc, None],
            [0, folder_23456_desc, None],
            [0, folder_34567_desc, None],
        ]

        output_head = 'Organization id'
        with captured_output() as (out, err):
            self.gcp_setup.get_organization()
            # collect all the output, the last line (excluding blank line)
            # should be 'Organization id: ...'
            all_output = [s for s in out.getvalue().split('\n') if len(s)]
            output = all_output[-1][:len(output_head)]
            self.assertEqual(output_head, output)

    def test_has_roles(self):
        """Test _has_roles()."""
        self.gcp_setup.authed_user = FAKE_ACCOUNT
        self.gcp_setup._run_command.return_value = [
            0,
            json.dumps(FAKE_IAM_POLICY),
            None
        ]

        with captured_output():
            # Does FAKE_ACCOUNT have "roles/fakeViewerRole"?
            actual = self.gcp_setup._has_roles('X', 1, ['roles/fakeViewerRole'])
            self.assertTrue(actual)

            # Does FAKE_ACCOUNT have "roles/fakeViewerRole" or
            # "roles/fakeAdminRole?
            actual = self.gcp_setup._has_roles('X', 1, [
                'roles/fakeViewerRole', 'roles/fakeAdminRole'])
            self.assertTrue(actual)

            # Does FAKE_ACCOUNT have "roles/fakeViewerRole" or
            # "roles/fakeEditorRole?
            actual = self.gcp_setup._has_roles('X', 1, [
                'roles/fakeEditorRole', 'roles/fakeViewerRole'])
            self.assertTrue(actual)

            # Does FAKE_ACCOUNT have "roles/fakeAdminRole"?
            actual = self.gcp_setup._has_roles('X', 1, [
                'roles/fakeAdminRole'])
            self.assertFalse(actual)


if __name__ == '__main__':
    unittest.main()
