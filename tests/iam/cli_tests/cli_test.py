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

""" Unit Tests: IAM Explain CLI. """

import shlex
import mock
import os
import json
import unittest
import StringIO
from copy import copy
from argparse import ArgumentParser

from tests.unittest_utils import ForsetiTestCase
from google.cloud.forseti.services import cli

CLIENT = mock.Mock()

CLIENT.playground = CLIENT

CLIENT.inventory = CLIENT
CLIENT.inventory.create = mock.Mock(return_value=iter(['test']))
CLIENT.inventory.get = mock.Mock(return_value='test')
CLIENT.inventory.delete = mock.Mock(return_value='test')

CLIENT.explain = CLIENT
CLIENT.explain.denormalize = mock.Mock(return_value=iter(['test']))


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

    def tearDown(self):
        """Bar."""
        os.environ = self.orig_env
        ForsetiTestCase.tearDown(self)

    @test_cmds([
        ('explainer list_models',     # Command line to call
         CLIENT.explain.list_models,  # Expected client function call
         [],                          # Expected args
         {},                          # Expected kwargs
         "{}",                        # .forseti config
         {}),                         # Expected attrib:value of parser config

        ('explainer delete_model foobar',
         CLIENT.explain.delete_model,
         ['foobar'],
         {},
         "{}",
         {}),

        ('explainer denormalize',
         CLIENT.explain.denormalize,
         [],
         {},
         "{}",
         {}),

        ('playground list_members',
         CLIENT.playground.list_members,
         [''],
         {},
         "{}",
         {}),

        ('inventory create --background --import_as "bar"',
         CLIENT.inventory.create,
         [True, 'bar'],
         {},
         "{}",
         {}),

        ('inventory get 1',
         CLIENT.inventory.get,
         [1],
         {},
         "{}",
         {}),

        ('inventory delete 1',
         CLIENT.inventory.delete,
         [1],
         {},
         "{}",
         {}),

        ('inventory delete 1',
         CLIENT.inventory.delete,
         [1],
         {},
         "{}",
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

        ])
    def test_cli(self, test_cases):
        """Test if the CLI hits specific client methods."""
        for commandline, client_func, func_args,\
            func_kwargs, config_string, config_expect\
                in test_cases:
            try:
                args = shlex.split(commandline)
                env_config = cli.DefaultConfig(
                    json.load(StringIO.StringIO(config_string)))

                config = cli.main(
                    args,
                    env_config,
                    CLIENT,
                    parser_cls=MockArgumentParser)

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
