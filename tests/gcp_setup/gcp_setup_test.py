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

from scripts.gcp_setup import setup_roles_apis
from scripts.gcp_setup.environment import gcloud_env
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
        self.gcp_setup.run_command = mock.MagicMock()

    def test_check_proper_gcloud(self):
        """Test check_proper_gcloud() works with proper version/alpha."""
        self.gcp_setup.run_command.return_value = [
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
        self.gcp_setup.run_command.return_value = [
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
        self.gcp_setup.run_command.return_value = [
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
        self.gcp_setup.run_command.return_value = [
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
        self.gcp_setup.run_command.return_value = [
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
        self.gcp_setup.run_command.return_value = [
            1,
            None,
            'Error output'
        ]
        with self.assertRaises(SystemExit):
            with captured_output():
                self.gcp_setup.check_proper_gcloud()

    def test_gcloud_info_json_fails(self):
        """Test gcloud_info() exits when json output fails."""
        self.gcp_setup.run_command.return_value = [
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
        self.gcp_setup.run_command.side_effect = [
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
        self.gcp_setup.run_command.return_value = [
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

    def test_sanitize_conf_values(self):
        """Test _sanitize_conf_values()."""
        self.assertTrue(
            all(self.gcp_setup._sanitize_conf_values(
                {
                    'test': None,
                    'test2': 3,
                    'test3': None,
                }
            )))
        self.assertTrue(
            all(self.gcp_setup._sanitize_conf_values(
                {
                    'test': '',
                    'test2': 1,
                    'test3': None,
                }
            )))


class SetupRolesTest(ForsetiTestCase):

    def setUp(self):
        self.parser = setup_roles_apis._create_arg_parser()
        self.args1 = ['--org-id', '1234', '--user', 'abc']
        self.args2 = ['--folder-id', '4567', '--group', 'def']
        self.args3 = ['--project-id', 'xyz', '--service-account', 'pqrs']

    def test_parse_args(self):
        """Test the arg parser with valid args."""
        args1 = self.parser.parse_args(self.args1)
        self.assertEqual(int(self.args1[1]), args1.org_id)
        self.assertEqual(self.args1[3], args1.user)

        args2 = self.parser.parse_args(self.args2)
        self.assertEqual(int(self.args2[1]), args2.folder_id)
        self.assertEqual(self.args2[3], args2.group)

        args3 = self.parser.parse_args(self.args3)
        self.assertEqual(self.args3[1], args3.project_id)
        self.assertEqual(self.args3[3], args3.service_account)

    def test_parse_args_fails(self):
        """Test some failing cases for the arg parser."""
        with captured_output() as (out, err):
            # Raises because --org-id should be an int
            with self.assertRaises(SystemExit):
                self.parser.parse_args(['--org-id', 'abc'])

            # Raises because --folder-id should be an int
            with self.assertRaises(SystemExit):
                self.parser.parse_args(['--folder-id', 'abc'])

            # Raises because no --user/--group/--service-account
            with self.assertRaises(SystemExit):
                self.parser.parse_args(['--project-id', 'abc'])

    def test_get_resource_info(self):
        """Test _get_resource_info()."""
        args1 = self.parser.parse_args(self.args1)
        res_args1, res_id1 = setup_roles_apis._get_resource_info(args1)
        self.assertEquals(int(self.args1[1]), res_id1)
        self.assertEquals(['organizations'], res_args1)

        args2 = self.parser.parse_args(self.args2)
        res_args2, res_id2 = setup_roles_apis._get_resource_info(args2)
        self.assertEquals(int(self.args2[1]), res_id2)
        self.assertEquals(['alpha', 'resource-manager', 'folders'], res_args2)

        args3 = self.parser.parse_args(self.args3)
        res_args3, res_id3 = setup_roles_apis._get_resource_info(args3)
        self.assertEquals(self.args3[1], res_id3)
        self.assertEquals(['projects'], res_args3)

    def test_get_member(self):
        """Test _get_member()."""
        args1 = self.parser.parse_args(self.args1)
        member_type1, member_name1 = setup_roles_apis._get_member(args1)
        self.assertEquals('user', member_type1)
        self.assertEquals(self.args1[3], member_name1)

        args2 = self.parser.parse_args(self.args2)
        member_type2, member_name2 = setup_roles_apis._get_member(args2)
        self.assertEquals('group', member_type2)
        self.assertEquals(self.args2[3], member_name2)

        args3 = self.parser.parse_args(self.args3)
        member_type3, member_name3 = setup_roles_apis._get_member(args3)
        self.assertEquals('serviceAccount', member_type3)
        self.assertEquals(self.args3[3], member_name3)


if __name__ == '__main__':
    unittest.main()
