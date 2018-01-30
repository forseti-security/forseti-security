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
import StringIO
import tempfile
import unittest

from google.cloud.forseti.services import cli
from tests.unittest_utils import ForsetiTestCase

CLIENT = mock.Mock()

CLIENT.inventory = CLIENT
CLIENT.inventory.create = mock.Mock(return_value=iter(['test']))
CLIENT.inventory.delete = mock.Mock(return_value='test')
CLIENT.inventory.list = mock.Mock(return_value=iter(['test']))
CLIENT.inventory.get = mock.Mock(return_value='test')

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
CLIENT.explain.denormalize = mock.Mock(return_value=iter(['test']))
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

CLIENT.playground = CLIENT
CLIENT.playground.add_role = mock.Mock(return_value='test')
CLIENT.playground.del_role = mock.Mock(return_value='test')
CLIENT.playground.add_member = mock.Mock(return_value='test')
CLIENT.playground.del_member = mock.Mock(return_value='test')
CLIENT.playground.set_iam_policy = mock.Mock(return_value='test')

CLIENT.scanner = CLIENT
CLIENT.scanner.run = mock.Mock(return_value=iter(['test']))


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
         [True, 'bar'],
         {},
         '{}',
         {}),

        ('inventory delete 1',
         CLIENT.inventory.delete,
         ['1'],
         {},
         '{}',
         {'endpoint': 'localhost:50051'}),

        ('inventory delete 1',
         CLIENT.inventory.delete,
         ['1'],
         {},
         '{"endpoint": "192.168.0.1:80"}',
         {'endpoint': '192.168.0.1:80'}),

        ('--endpoint 10.0.0.1:8080 inventory delete 1',
         CLIENT.inventory.delete,
         ['1'],
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
         ['1'],
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
         ["foo"],
         {},
         '{"endpoint": "192.168.0.1:80"}',
         {'endpoint': '192.168.0.1:80'}),

        ('model create inventory foo --id 1',
         CLIENT.model.new_model,
         ["inventory", "foo", '1', False],
         {},
         '{"endpoint": "192.168.0.1:80"}',
         {'endpoint': '192.168.0.1:80'}),

        ('explainer denormalize',
         CLIENT.explain.denormalize,
         [],
         {},
         '{}',
         {}),

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

        ('explainer why_granted member/foo resource/bar',
         CLIENT.explain.explain_granted,
         ['member/foo', 'resource/bar', None, None],
         {},
         '{}',
         {}),

        ('explainer why_denied member/foo resource/bar --role role/r1',
         CLIENT.explain.explain_denied,
         ['member/foo', ['resource/bar'], ['role/r1'], []],
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

        ('explainer access_by_resource resource/foo --expand_groups True',
         CLIENT.explain.query_access_by_resources,
         ['resource/foo', [], True],
         {},
         '{}',
         {}),

        ('playground define_role resource/foo permission/a permission/b',
         CLIENT.playground.add_role,
         ['resource/foo', ['permission/a', 'permission/b']],
         {},
         '{}',
         {}),

        ('playground delete_role resource/foo',
         CLIENT.playground.del_role,
         ['resource/foo'],
         {},
         '{}',
         {}),

        ('playground define_member member/child member/parent',
         CLIENT.playground.add_member,
         ['member/child', ['member/parent']],
         {},
         '{}',
         {}),

        ('playground delete_member member/foo',
         CLIENT.playground.del_member,
         ['member/foo', '', False],
         {},
         '{}',
         {}),

        ('playground set_policy resource/foo {\\\"foo\\\":\\\"bar\\\"}',
         CLIENT.playground.set_iam_policy,
         ['resource/foo', {'foo': 'bar'}],
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

        ('scanner run /tmp/config',
         CLIENT.scanner.run,
         ['/tmp/config'],
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

    def test_cli(self, test_cases):
        """Test if the CLI hits specific client methods."""
        tmp_config = os.path.join(self.test_dir, '.forseti')
        with mock.patch.dict(
            os.environ, {'FORSETI_CLIENT_CONFIG': tmp_config}):
            for commandline, client_func, func_args,\
                func_kwargs, config_string, config_expect\
                    in test_cases:
                try:
                    args = shlex.split(commandline)
                    env_config = cli.DefaultConfig(
                        json.load(StringIO.StringIO(config_string)))
                    config = cli.main(
                        args=args,
                        config_env=env_config,
                        client=CLIENT,
                        parser_cls=MockArgumentParser)
                    if client_func is not None:
                        client_func.assert_called_with(*func_args, **func_kwargs)

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


if __name__ == '__main__':
    unittest.main()
