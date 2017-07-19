# Copyright 2017 Google Inc.
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
import unittest
from copy import copy
from argparse import ArgumentParser

from tests.unittest_utils import ForsetiTestCase
from google.cloud.security.iam import cli

CLIENT = mock.Mock()
CLIENT.playground = CLIENT
CLIENT.explainer = CLIENT


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
        ('explainer list_models',
         CLIENT.explain.list_models,
         [],
         {}),

        ('playground list_members',
         CLIENT.playground.list_members,
         [''],
         {}),
        ])
    def test_cli(self, test_cases):
        """Foo."""
        for commandline, client_func, func_args, func_kwargs in test_cases:
            try:
                args = shlex.split(commandline)
                cli.main(args, CLIENT, parser_cls=MockArgumentParser)
                client_func.assert_called_with(*func_args, **func_kwargs)
            except ArgumentParserError as e:
                self.fail('Argument parser failed on {}, {}'.format(
                    commandline,
                    e.message))


if __name__ == '__main__':
    unittest.main()

