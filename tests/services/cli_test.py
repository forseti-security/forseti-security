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
"""Unit Tests: Forseti CLI."""

from argparse import ArgumentParser
from copy import copy
import json
import mock
import os
import shlex
import shutil
import sys
import StringIO
import tempfile
import unittest

import grpc

from google.cloud.forseti.services import cli
from tests.unittest_utils import ForsetiTestCase

CLIENT = mock.Mock()

CLIENT.inventory = CLIENT
CLIENT.inventory.create = mock.Mock(return_value=iter(['test']))
CLIENT.inventory.delete = mock.Mock(return_value='test')
CLIENT.inventory.list = mock.Mock(return_value=iter(['test']))
CLIENT.inventory.get = mock.Mock(return_value='test')

# list raises server unavailable
ERROR_CLIENT = mock.Mock()
ERROR_CLIENT.inventory = ERROR_CLIENT
ERROR_CLIENT.inventory.list = mock.Mock()
grpc_server_unavailable = grpc.RpcError()
grpc_server_unavailable.code = lambda: grpc.StatusCode.UNAVAILABLE
ERROR_CLIENT.inventory.list.side_effect = grpc_server_unavailable

# get raises server unknown
ERROR_CLIENT.inventory.get = mock.Mock()
grpc_unknown_error = grpc.RpcError()
grpc_unknown_error.code = lambda: grpc.StatusCode.UNKNOWN
ERROR_CLIENT.inventory.get.side_effect = grpc_unknown_error

reply_model_s = mock.Mock()
reply_model_s.status = "SUCCESS"
reply_model_s.handle = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
reply_model_b = mock.Mock()
reply_model_b.status = "BROKEN"
CLIENT.model = CLIENT
CLIENT.model.list_models = mock.Mock(return_value=iter(['test']))
CLIENT.model.get_model = mock.Mock(return_value=reply_model_s)
CLIENT.model.delete_model = mock.Mock(return_value='test')
CLIENT.model.new_model = mock.Mock(return_value='test')

CLIENT.explain = CLIENT
CLIENT.explain.list_resources = mock.Mock(return_value='test')
CLIENT.explain.list_members = mock.Mock(return_value='test')
CLIENT.explain.list_roles = mock.Mock(return_value='test')
CLIENT.explain.query_permissions_by_roles = mock.Mock(return_value='test')
CLIENT.explain.get_iam_policy = mock.Mock(return_value='test')
CLIENT.explain.check_iam_policy = mock.Mock(return_value='test')
CLIENT.explain.explain_granted = mock.Mock(return_value='test')
CLIENT.explain.explain_denied = mock.Mock(return_value='test')
CLIENT.explain.query_access_by_members = mock.Mock(return_value='test')
CLIENT.explain.query_access_by_permissions = mock.Mock(return_value=iter(['test']))
CLIENT.explain.query_access_by_resources = mock.Mock(return_value='test')


class Progress(object):
    def __init__(self, message):
        self.message = message


CLIENT.scanner = CLIENT
CLIENT.scanner.run = mock.Mock(return_value=iter([Progress('test')]))

CLIENT.notifier = CLIENT
CLIENT.notifier.run = mock.Mock(return_value=iter([Progress('test')]))


class ArgumentParserError(Exception):
    pass


class MockArgumentParser(ArgumentParser):

    def error(self, message):
        raise ArgumentParserError(message)


def test_cmds(args):
    def decorator(f):
        def wrapper(*original_args):
            original_args = list(original_args)
            original_args.append(args)
            return f(*original_args)
        return wrapper
    return decorator


class ImporterTest(ForsetiTestCase):

    def setUp(self):
        """Foo."""
        ForsetiTestCase.setUp(self)
        self.orig_env = copy(os.environ)
        os.environ['IAM_MODEL'] = 'da39a3ee5e6b4b0d3255bfef95601890afd80709'
        self.test_dir = tempfile.mkdtemp()

    def tearDown(self):
        """Bar."""
        shutil.rmtree(self.test_dir)
        os.environ = self.orig_env
        ForsetiTestCase.tearDown(self)

    @test_cmds([
        ('inventory create --background --import_as "bar"',
         CLIENT.inventory.create,
         [True, 'bar', False],
         {},
         '{}',
         {}),

        ('inventory delete 1',
         CLIENT.inventory.delete,
         [1],
         {},
         '{}',
         {'endpoint': 'localhost:50051'}),

        ('inventory delete 1',
         CLIENT.inventory.delete,
         [1],
         {},
         '{"endpoint": "192.168.0.1:80"}',
         {'endpoint': '192.168.0.1:80'}),

        ('--endpoint 10.0.0.1:8080 inventory delete 1',
         CLIENT.inventory.delete,
         [1],
         {},
         '{"endpoint": "192.168.0.1:80"}',
         {'endpoint': '10.0.0.1:8080'}),

        ('inventory list',
         CLIENT.inventory.list,
         [],
         {},
         '{}',
         {}),

        ('inventory get 1',
         CLIENT.inventory.get,
         [1],
         {},
         '{}',
         {}),

        ('model use foo',
         CLIENT.model.get_model,
         ["foo"],
         {},
         '{"endpoint": "192.168.0.1:80"}',
         {'endpoint': '192.168.0.1:80'}),

        ('model list',
         CLIENT.model.list_models,
         [],
         {},
         '{"endpoint": "192.168.0.1:80"}',
         {'endpoint': '192.168.0.1:80'}),

        ('model get foo',
         CLIENT.model.get_model,
         ["foo"],
         {},
         '{"endpoint": "192.168.0.1:80"}',
         {'endpoint': '192.168.0.1:80'}),

        ('model delete foo',
         CLIENT.model.delete_model,
         ['da39a3ee5e6b4b0d3255bfef95601890afd80709'],
         {},
         '{"endpoint": "192.168.0.1:80"}',
         {'endpoint': '192.168.0.1:80'}),

        ('model create --inventory_index_id 1 foo',
         CLIENT.model.new_model,
         ["inventory", "foo", 1, False],
         {},
         '{"endpoint": "192.168.0.1:80"}',
         {'endpoint': '192.168.0.1:80'}),

        ('explainer list_resources',
         CLIENT.explain.list_resources,
         [''],
         {},
         '{}',
         {}),

        ('explainer list_members',
         CLIENT.explain.list_members,
         [''],
         {},
         '{}',
         {}),

        ('explainer list_roles',
         CLIENT.explain.list_roles,
         [''],
         {},
         '{}',
         {}),

        ('explainer list_permissions --roles roles/foo',
         CLIENT.explain.query_permissions_by_roles,
         [['roles/foo'],[]],
         {},
         '{}',
         {}),

        ('explainer get_policy resource/foo',
         CLIENT.explain.get_iam_policy,
         ['resource/foo'],
         {},
         '{}',
         {}),

        ('explainer check_policy resource/foo permission/bar member/Adam',
         CLIENT.explain.check_iam_policy,
         ['resource/foo', 'permission/bar', 'member/Adam'],
         {},
         '{}',
         {}),

        ('explainer why_granted member/foo resource/bar --role role/r1',
         CLIENT.explain.explain_granted,
         ['member/foo', 'resource/bar', 'role/r1', None],
         {},
         '{}',
         {}),

        ('explainer why_granted member/foo resource/bar --permission permission/p1',
         CLIENT.explain.explain_granted,
         ['member/foo', 'resource/bar', None, 'permission/p1'],
         {},
         '{}',
         {}),

        ('explainer why_denied member/foo resource/bar --role role/r1',
         CLIENT.explain.explain_denied,
         ['member/foo', ['resource/bar'], ['role/r1'], []],
         {},
         '{}',
         {}),

        ('explainer why_denied member/foo resource/bar --permission permission/p1',
         CLIENT.explain.explain_denied,
         ['member/foo', ['resource/bar'], [], ['permission/p1']],
         {},
         '{}',
         {}),

        ('explainer access_by_member member/foo',
         CLIENT.explain.query_access_by_members,
         ['member/foo', [], False],
         {},
         '{}',
         {}),

        ('explainer access_by_authz --role role/foo',
         CLIENT.explain.query_access_by_permissions,
         ['role/foo', None, False, False],
         {},
         '{}',
         {}),

        ('explainer access_by_resource resource/foo --expand_groups',
         CLIENT.explain.query_access_by_resources,
         ['resource/foo', [], True],
         {},
         '{}',
         {}),

        ('config show',
         None,
         [],
         {},
         '{"endpoint": "192.168.0.1:80"}',
         {'endpoint': '192.168.0.1:80'}),

        ('config model foo',
         None,
         [],
         {},
         '{"endpoint": "192.168.0.1:80"}',
         {'endpoint': '192.168.0.1:80'}),

        ('scanner run',
         CLIENT.scanner.run,
         [None],
         {},
         '{"endpoint": "192.168.0.1:80"}',
         {'endpoint': '192.168.0.1:80'}),

        ('scanner run --scanner external_project_access_scanner',
         CLIENT.scanner.run,
         ['external_project_access_scanner'],
         {},
         '{"endpoint": "192.168.0.1:80"}',
         {'endpoint': '192.168.0.1:80'}),

        ('notifier run --inventory_index_id 88',
         CLIENT.scanner.run,
         [88, 0],
         {},
         '{"endpoint": "192.168.0.1:80"}',
         {'endpoint': '192.168.0.1:80'}),

        ('notifier run --scanner_index_id 88',
         CLIENT.scanner.run,
         [0, 88],
         {},
         '{"endpoint": "192.168.0.1:80"}',
         {'endpoint': '192.168.0.1:80'}),

        ('notifier run --inventory_index_id 88 --scanner_index_id 88',
         CLIENT.scanner.run,
         [88, 88],
         {},
         '{"endpoint": "192.168.0.1:80"}',
         {'endpoint': '192.168.0.1:80'}),

        ('config endpoint 192.168.0.1:80',
         None,
         [],
         {},
         '{"endpoint": "192.168.0.1:80"}',
         {'endpoint': '192.168.0.1:80'}),

        ('config format json',
         None,
         [],
         {},
         '{"endpoint": "192.168.0.1:80"}',
         {'endpoint': '192.168.0.1:80'}),

        ('config model foobar',
         None,
         [],
         {},
         '{"endpoint": "192.168.0.1:80"}',
         {'endpoint': '192.168.0.1:80'}),
        ])
    @mock.patch('google.cloud.forseti.services.cli.MessageToJson', mock.MagicMock())
    def test_cli(self, test_cases):
        """Test if the CLI hits specific client methods."""
        tmp_config = os.path.join(self.test_dir, '.forseti')
        with mock.patch.dict(
            os.environ, {'FORSETI_CLIENT_CONFIG': tmp_config}):
            for (commandline, client_func, func_args,
                    func_kwargs, config_string, config_expect) in test_cases:
                try:
                    args = shlex.split(commandline)
                    env_config = cli.DefaultConfig(
                        json.load(StringIO.StringIO(config_string)))
                    # Capture stdout, so it doesn't pollute the test output
                    with mock.patch('sys.stdout',
                                    new_callable=StringIO.StringIO):
                        config = cli.main(
                            args=args,
                            config_env=env_config,
                            client=CLIENT,
                            parser_cls=MockArgumentParser)
                    if client_func is not None:
                        client_func.assert_called_with(*func_args,
                                                       **func_kwargs)

                    # Check attribute values
                    for attribute, value in config_expect.iteritems():
                        self.assertEqual(
                            getattr(config, attribute),
                            value,
                            'Attribute value unexpected: {}, {}'.format(
                                attribute,
                                value))

                except ArgumentParserError as e:
                    self.fail('Argument parser failed on {}, {}'.format(
                        commandline,
                        e.message))

    @test_cmds([
            ('inventory list',
             ERROR_CLIENT.inventory.list,
             [],
             {},
             '{}',
             {})])
    def test_cli_grpc_server_unavailable(self, test_cases):
        """Grpc server unavailable."""
        for (commandline, client_func, func_args,
             func_kwargs, config_string, config_expect) in test_cases:
            args = shlex.split(commandline)
            env_config = cli.DefaultConfig(
                json.load(StringIO.StringIO(config_string)))
            with mock.patch('sys.stdout',
                            new_callable=StringIO.StringIO) as mock_out:
                cli.main(
                    args=args,
                    config_env=env_config,
                    client=ERROR_CLIENT,
                    parser_cls=MockArgumentParser)
                cli_output = mock_out.getvalue().strip()
                self.assertTrue('Error communicating to the Forseti server.' in cli_output)

    @test_cmds([
            ('inventory get 123',
             ERROR_CLIENT.inventory.get,
             [],
             {},
             '{}',
             {})])
    def test_cli_grpc_server_unknown(self, test_cases):
        """Grpc server unavailable."""
        for (commandline, client_func, func_args,
             func_kwargs, config_string, config_expect) in test_cases:
            args = shlex.split(commandline)
            env_config = cli.DefaultConfig(
                json.load(StringIO.StringIO(config_string)))
            with mock.patch('sys.stdout',
                            new_callable=StringIO.StringIO) as mock_out:
                cli.main(
                    args=args,
                    config_env=env_config,
                    client=ERROR_CLIENT,
                    parser_cls=MockArgumentParser)
                cli_output = mock_out.getvalue().strip()
                self.assertTrue('Error occurred on the server side' in cli_output)


class RunExplainerTest(ForsetiTestCase):
    def test_list_permissions_no_roles_and_no_role_prefixes(self):
        ignored = mock.MagicMock()
        mock_client = mock.MagicMock()
        mock_config = mock.MagicMock()
        mock_config.action = 'list_permissions'
        mock_config.roles = None
        mock_config.role_prefixes = None
        mock_output = mock.MagicMock()
        with self.assertRaises(ValueError) as ctxt:
            cli.run_explainer(mock_client, mock_config, mock_output, ignored)
        self.assertEquals(
            'please specify either a role or a role prefix',
            ctxt.exception.message)

    def test_list_permissions_with_role_specified(self):
        ignored = mock.MagicMock()
        mock_client = mock.MagicMock()
        mock_config = mock.MagicMock()
        mock_config.action = 'list_permissions'
        mock_config.roles = ['r1']
        mock_config.role_prefixes = None
        mock_output = mock.MagicMock()
        cli.run_explainer(mock_client, mock_config, mock_output, ignored)

    def test_list_permissions_with_role_prefix_specified(self):
        ignored = mock.MagicMock()
        mock_client = mock.MagicMock()
        mock_config = mock.MagicMock()
        mock_config.action = 'list_permissions'
        mock_config.roles = []
        mock_config.role_prefixes = ['rp1']
        mock_output = mock.MagicMock()
        cli.run_explainer(mock_client, mock_config, mock_output, ignored)

    def test_query_access_by_authz_with_no_role_and_no_permission(self):
        ignored = mock.MagicMock()
        mock_client = mock.MagicMock()
        mock_config = mock.MagicMock()
        mock_config.action = 'access_by_authz'
        mock_config.role = None
        mock_config.permission = None
        mock_output = mock.MagicMock()
        with self.assertRaises(ValueError) as ctxt:
            cli.run_explainer(mock_client, mock_config, mock_output, ignored)
        self.assertEquals(
            'please specify either a role or a permission',
            ctxt.exception.message)

    def test_query_access_by_authz_with_role_specified(self):
        ignored = mock.MagicMock()
        mock_client = mock.MagicMock()
        mock_config = mock.MagicMock()
        mock_config.action = 'access_by_authz'
        mock_config.role = ['role']
        mock_config.permission = None
        mock_output = mock.MagicMock()
        cli.run_explainer(mock_client, mock_config, mock_output, ignored)

    def test_query_access_by_authz_with_permission_specified(self):
        ignored = mock.MagicMock()
        mock_client = mock.MagicMock()
        mock_config = mock.MagicMock()
        mock_config.action = 'access_by_authz'
        mock_config.role = []
        mock_config.permission = ['permission']
        mock_output = mock.MagicMock()
        cli.run_explainer(mock_client, mock_config, mock_output, ignored)


class MainTest(ForsetiTestCase):
    def test_main_with_value_error_raised(self):
        mock_client = mock.MagicMock()
        mock_parser = mock.MagicMock()
        mock_config_env = mock.MagicMock()
        mock_config = mock.MagicMock()
        mock_config.action = 'list_permissions'
        mock_config.roles = None
        mock_config.role_prefixes = None
        mock_config.out_format = 'json'
        mock_config.service = 'explainer'
        with mock.patch('google.cloud.forseti.services.cli.create_parser') as mock_create_parser:
            mock_create_parser.return_value = mock_parser
            mock_parser.parse_args.return_value = mock_config
            cli.main([], mock_config_env, mock_client)
            mock_parser.error.assert_called_with(
                'please specify either a role or a role prefix')

    def test_main_without_value_error_raised(self):
        mock_client = mock.MagicMock()
        mock_parser = mock.MagicMock()
        mock_config_env = mock.MagicMock()
        mock_config = mock.MagicMock()
        mock_config.action = 'list_permissions'
        mock_config.roles = ['r1', 'r2']
        mock_config.role_prefixes = None
        mock_config.out_format = 'json'
        mock_config.service = 'explainer'
        with mock.patch('google.cloud.forseti.services.cli.create_parser') as mock_create_parser:
            mock_create_parser.return_value = mock_parser
            mock_parser.parse_args.return_value = mock_config
            cli.main([], mock_config_env, mock_client)
            mock_parser.error.assert_not_called()


if __name__ == '__main__':
    unittest.main()
