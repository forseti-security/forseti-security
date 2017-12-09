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

from scripts.gcp_setup.environment import gcloud_env
from scripts.gcp_setup.environment import utils
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


class GcloudEnvTest(ForsetiTestCase):
    """Test the gcp_setup."""

    def setUp(self):
        self.gcp_setup = gcloud_env.ForsetiGcpSetup()
        utils.run_command = mock.MagicMock()
        gcloud_env.GCLOUD_MIN_VERSION = GCLOUD_MIN_VERSION
        self.gcloud_min_ver_formatted = '.'.join([str(d) for d in GCLOUD_MIN_VERSION])

    def test_check_proper_gcloud(self):
        """Test check_proper_gcloud() works with proper version/alpha."""
        utils.run_command.return_value = (
            0,
            'Google Cloud SDK %s\nalpha 12345\netc' % self.gcloud_min_ver_formatted,
            None
        )
        output_head = 'Current gcloud version'
        with captured_output() as (out, err):
            gcloud_env.check_proper_gcloud()
            output = out.getvalue()[:len(output_head)]
            self.assertEqual(output_head, output)

    def test_check_proper_gcloud_failed_command(self):
        """Test check_proper_gcloud() exits when command fails."""
        utils.run_command.return_value = (
            1,
            'Google Cloud SDK %s\nalpha 12345\netc' % self.gcloud_min_ver_formatted,
            None
        )
        output_head = 'Error'
        with self.assertRaises(SystemExit):
            with captured_output() as (out, err):
                gcloud_env.check_proper_gcloud()
                output = out.getvalue()[:len(output_head)]
                self.assertEqual(output_head, output)

    def test_check_proper_gcloud_low_version(self):
        """Test check_proper_gcloud() exits with low gcloud version."""
        utils.run_command.return_value = (
            0,
            'Google Cloud SDK 162.9.9\nalpha 12345\netc',
            None
        )
        output_head = ('Current gcloud version: %s\n'
                       'Has alpha components? True'
                       'You need' % self.gcloud_min_ver_formatted)
        with self.assertRaises(SystemExit):
            with captured_output() as (out, err):
                gcloud_env.check_proper_gcloud()
                output = out.getvalue()[:len(output_head)]

    def test_check_proper_gcloud_no_alpha(self):
        """Test check_proper_gcloud() exits with no alpha components."""
        utils.run_command.return_value = (
            0,
            'Google Cloud SDK %s\netc' % self.gcloud_min_ver_formatted,
            None
        )
        output_head = ('Current gcloud version: %s\n'
                       'Has alpha components? False\n'
                       'You need' % self.gcloud_min_ver_formatted)
        with self.assertRaises(SystemExit):
            with captured_output() as (out, err):
                gcloud_env.check_proper_gcloud()
                output = out.getvalue()[:len(output_head)]
                self.assertEqual(output_head, output)

    def test_gcloud_info_works_nocloudshell(self):
        """Test gcloud_info()."""
        utils.run_command.return_value = (
            0,
            json.dumps(FAKE_GCLOUD_INFO),
            None
        )
        with captured_output() as (out, err):
            self.gcp_setup.gcloud_info()
            output = out.getvalue().strip()
            self.assertEqual('Read gcloud info successfully', output)

    def test_gcloud_info_cmd_fails(self):
        """Test gcloud_info() exits when command fails."""
        utils.run_command.return_value = (
            1,
            None,
            'Error output'
        )
        with self.assertRaises(SystemExit):
            with captured_output():
                gcloud_env.check_proper_gcloud()

    def test_gcloud_info_json_fails(self):
        """Test gcloud_info() exits when json output fails."""
        utils.run_command.return_value = (
            0,
            'invalid json',
            None,
        )
        with self.assertRaises(SystemExit):
            with captured_output():
                self.gcp_setup.gcloud_info()

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

    def test_check_authed_user(self):
        """Test check_authed_user()."""
        with self.assertRaises(SystemExit):
            with captured_output():
                self.gcp_setup.check_authed_user()

        self.gcp_setup.authed_user = FAKE_ACCOUNT
        output_head = 'You are'
        with captured_output() as (out, err):
            self.gcp_setup.check_authed_user()
            output = out.getvalue()[:len(output_head)]
            self.assertEqual(output_head, output)

    def test_check_project_id(self):
        """Test check_project_id()."""
        with self.assertRaises(SystemExit):
            with captured_output():
                self.gcp_setup.check_project_id()

        self.gcp_setup.project_id = FAKE_PROJECT
        output_head = 'Project id'
        with captured_output() as (out, err):
            self.gcp_setup.check_project_id()
            output = out.getvalue()[:len(output_head)]
            self.assertEqual(output_head, output)

    def test_lookup_organization(self):
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
        self.gcp_setup.project_id = FAKE_PROJECT
        utils.run_command.side_effect = [
            [0, project_desc, None],
            [0, folder_12345_desc, None],
            [0, folder_23456_desc, None],
            [0, folder_34567_desc, None],
        ]

        output_head = 'Organization id'
        with captured_output() as (out, err):
            self.gcp_setup.lookup_organization()
            # collect all the output, the last line (excluding blank line)
            # should be 'Organization id: ...'
            all_output = [s for s in out.getvalue().split('\n') if len(s)]
            output = all_output[-1][:len(output_head)]
            self.assertEqual(output_head, output)

    def test_sanitize_conf_values(self):
        """Test sanitize_conf_values()."""
        self.assertTrue(
            all(gcloud_env.sanitize_conf_values(
                {
                    'test': None,
                    'test2': 3,
                    'test3': None,
                }
            )))
        self.assertTrue(
            all(gcloud_env.sanitize_conf_values(
                {
                    'test': '',
                    'test2': 1,
                    'test3': None,
                }
            )))

    def test_id_from_name(self):
        """Test extracting id from resource name."""
        self.assertEquals('24680', gcloud_env.id_from_name('organizations/24680'))
        self.assertEquals('9987', gcloud_env.id_from_name('folders/9987'))
        self.assertEquals('abc', gcloud_env.id_from_name('projects/abc'))
        self.assertEquals('123', gcloud_env.id_from_name('fake/123'))

    @mock.patch('__builtin__.open', spec=open)
    def test_get_forseti_version(self, mock_open):
        """Test getting Forseti version from version file."""
        fake_version = 'vTESTTEST'
        mock_handler = mock.MagicMock()
        mock_handler.__enter__.return_value.__iter__.return_value = (
            'junk line',
            'more junk',
            '__version__ = \'%s\'' % fake_version,
            'even more junk',
        )
        mock_handler.__exit__.return_value = False
        mock_open.return_value = mock_handler
        self.assertEqual(fake_version, gcloud_env.get_forseti_version())

    def test_get_remote_branches(self):
        """Test get_remote_branches()."""
        utils.run_command.return_value = (
            0,
            '',
            None
        )
        self.assertEquals([], gcloud_env.get_remote_branches())

        utils.run_command.return_value = (
            0,
            ' origin/branch-a\n origin/branch-b\n origin/master',
            None
        )
        self.assertEquals(
            ['origin/branch-a', 'origin/branch-b', 'origin/master'],
            gcloud_env.get_remote_branches())

    def test_enable_apis(self):
        """Test enable_apis()."""
        utils.run_command.return_value = (0, '', None)
        output_tail = 'Done.'
        with captured_output() as (out, err):
            gcloud_env.enable_apis()
            # collect all the output, the last line (excluding blank line)
            all_output = [s for s in out.getvalue().split('\n') if len(s)]
            output = all_output[-1][:len(output_tail)]
            self.assertEqual(output_tail, output)

    def test_full_service_acct_email(self):
        """Test full_service_acct_email()."""
        fake_acct_id = 'test-robot'
        fake_project = 'test-project'
        self.assertEquals(
            gcloud_env.SERVICE_ACCT_EMAIL_FMT.format(fake_acct_id, fake_project),
            gcloud_env.full_service_acct_email(fake_acct_id, fake_project))

    @mock.patch('__builtin__.raw_input', side_effect=['y'])
    def test_should_setup_explain(self, mock_rawinput):
        """Test should_setup_explain()."""
        with captured_output() as (out, err):
            self.gcp_setup.should_setup_explain()
            self.assertTrue(self.gcp_setup.setup_explain)

        self.gcp_setup.advanced_mode = True
        with captured_output() as (out, err):
            self.gcp_setup.should_setup_explain()
            self.assertTrue(self.gcp_setup.setup_explain)

    @mock.patch('__builtin__.raw_input')
    def test_determine_access_target_orgs(self, mock_rawinput):
        """Test determine_access_target() for organizations."""
        fake_org_id = '1234567890'
        self.gcp_setup.organization_id = fake_org_id
        mock_rawinput.side_effect = ['1', fake_org_id]

        with captured_output() as (out, err):
            self.gcp_setup.determine_access_target()
            self.assertEqual(
                'organizations/%s' % fake_org_id, self.gcp_setup.resource_root_id)

        self.gcp_setup.advanced_mode = True
        self.gcp_setup.setup_explain = True
        with captured_output() as (out, err):
            self.gcp_setup.determine_access_target()
            self.assertEqual(
                'organizations/%s' % fake_org_id, self.gcp_setup.resource_root_id)

        self.gcp_setup.setup_explain = False
        with captured_output() as (out, err):
            self.gcp_setup.determine_access_target()
            self.assertEqual(
                'organizations/%s' % fake_org_id, self.gcp_setup.resource_root_id)

    @mock.patch('__builtin__.raw_input')
    def test_determine_access_target_folders(self, mock_rawinput):
        """Test determine_access_target() for folders."""
        fake_folder_id = '334455'
        mock_rawinput.side_effect = ['2', fake_folder_id]

        self.gcp_setup.advanced_mode = True
        self.gcp_setup.setup_explain = False
        with captured_output() as (out, err):
            self.gcp_setup.determine_access_target()
            self.assertEqual(
                'folders/%s' % fake_folder_id, self.gcp_setup.resource_root_id)

    @mock.patch('__builtin__.raw_input')
    def test_determine_access_target_projects(self, mock_rawinput):
        """Test determine_access_target() for projects."""
        fake_project_id = 'project-abc'
        mock_rawinput.side_effect = ['3', fake_project_id]

        self.gcp_setup.advanced_mode = True
        self.gcp_setup.setup_explain = False
        with captured_output() as (out, err):
            self.gcp_setup.determine_access_target()
            self.assertEqual(
                'projects/%s' % fake_project_id, self.gcp_setup.resource_root_id)

    @mock.patch('__builtin__.raw_input')
    def test_choose_organization(self, mock_rawinput):
        """Test choose_organization()."""
        # No orgs
        utils.run_command.return_value = (0, '{}', None)
        with captured_output() as (out, err):
            self.gcp_setup.choose_organization()
            self.assertEqual(None, self.gcp_setup.target_id)

        mock_rawinput.side_effect = ['abc', '123']
        # Has orgs
        utils.run_command.return_value = (
            0, '[{"name": "organizations/123", "displayName": "fake org"}]', None)
        with captured_output() as (out, err):
            self.gcp_setup.choose_organization()
            self.assertEqual('123', self.gcp_setup.target_id)

    @mock.patch('__builtin__.raw_input')
    def test_choose_folder(self, mock_rawinput):
        """Test choose_folder()."""
        mock_rawinput.side_effect = ['abc', '123']
        # Has orgs
        with captured_output() as (out, err):
            self.gcp_setup.choose_folder()
            self.assertEqual('123', self.gcp_setup.target_id)

    @mock.patch('__builtin__.raw_input')
    def test_choose_project(self, mock_rawinput):
        """Test choose_project()."""
        mock_rawinput.side_effect = ['abc']
        # Has orgs
        with captured_output() as (out, err):
            self.gcp_setup.choose_project()
            self.assertEqual('abc', self.gcp_setup.target_id)

    @mock.patch('__builtin__.raw_input')
    def test_should_enable_write_access_true(self, mock_rawinput):
        """Test should_enable_write_access()."""
        with captured_output() as (out, err):
            self.gcp_setup.should_enable_write_access()
            self.assertTrue(self.gcp_setup.enable_write_access)

    @mock.patch('__builtin__.raw_input')
    def test_should_enable_write_access_false(self, mock_rawinput):
        """Test should_enable_write_access(), in the "no" case."""
        self.gcp_setup.advanced_mode = True
        mock_rawinput.side_effect = ['n']
        with captured_output() as (out, err):
            self.gcp_setup.should_enable_write_access()
            self.assertFalse(self.gcp_setup.enable_write_access)

    def test_format_service_acct_ids(self):
        """Test format_service_acct_ids()."""
        self.gcp_setup.project_id = 'fake-project'
        self.gcp_setup.timestamp = '1'
        gcp_email_1 = gcloud_env.full_service_acct_email(
            gcloud_env.SERVICE_ACCT_FMT.format(
                'gcp', 'reader', self.gcp_setup.timestamp),
            self.gcp_setup.project_id)
        gsuite_email_1 = gcloud_env.full_service_acct_email(
            gcloud_env.SERVICE_ACCT_FMT.format(
                'gsuite', 'reader', self.gcp_setup.timestamp),
            self.gcp_setup.project_id)
        self.gcp_setup.format_service_acct_ids()
        self.assertEquals(gcp_email_1, self.gcp_setup.gcp_service_account)
        self.assertEquals(gsuite_email_1, self.gcp_setup.gsuite_service_account)

        self.gcp_setup.enable_write_access = True
        gcp_email_2 = gcloud_env.full_service_acct_email(
            gcloud_env.SERVICE_ACCT_FMT.format(
                'gcp', 'readwrite', self.gcp_setup.timestamp),
            self.gcp_setup.project_id)
        self.gcp_setup.format_service_acct_ids()
        self.assertEquals(gcp_email_2, self.gcp_setup.gcp_service_account)

    def test_inform_access_on_target_basic(self):
        """Test inform_access_on_target()."""
        with captured_output() as (out, err):
            self.gcp_setup.inform_access_on_target()
            self.assertTrue(self.gcp_setup.user_can_grant_roles)

    @mock.patch('__builtin__.raw_input')
    def test_inform_access_on_target_advanced(self, mock_rawinput):
        """Test inform_access_on_target()."""
        self.gcp_setup.advanced_mode = True
        mock_rawinput.side_effect = ['y', 'n']

        with captured_output() as (out, err):
            self.gcp_setup.inform_access_on_target()
            self.assertTrue(self.gcp_setup.user_can_grant_roles)

        with captured_output() as (out, err):
            self.gcp_setup.inform_access_on_target()
            self.assertFalse(self.gcp_setup.user_can_grant_roles)


if __name__ == '__main__':
    unittest.main()
