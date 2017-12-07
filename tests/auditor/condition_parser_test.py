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

"""Rule condition parser tests."""

import mock
import unittest

import pyparsing

from google.cloud.forseti.auditor import condition_parser as cp
from tests.unittest_utils import ForsetiTestCase


def parse(filter_expr, expected, params, parser=None):
    """Parse the expression.

    This wraps the eval_filter() method from the parser.

    Args:
        filter_expr (str): The expression to evaluate.
        expected (bool): The expected result.
        params (dict): The parameters to use for variable lookups.
        parser (object): The parser to use for parsing the expression.

    Raises:
        AssertionError: If the results do not equal the expected value.
    """
    if not parser:
        parser = ConditionParser(params)

    result = parser.eval_filter(filter_expr)
    if result != expected:
        raise AssertionError("yields %s instead of %s" % (result, expected))


class ConditionParserTest(ForsetiTestCase):
    """ConditionParserTest."""

    def setUp(self):
        """Setup."""
        pass

    def test_conditions_parse_successfully(self):
        """Test that the following conditions parse without error."""
        parameters = {
            'test_var': 100,
            'some_val': 'A',
        }
        tests = [
            # Filter_string, Expected_result)
            ("199 / 2 > test_var", False),
            ("101 == test_var + 1", True),
            ("5 + 45 * 2 > test_var", False),
            ("-5+5 < test_var", True),
            ("some_val == 'N'", False),
            ("1", True),
            ("0", False),
            ("test_var - 100 == 0", True),
            ("test_var == 1 and some_val == 'T'", False),
            ("test_var != 1 and not some_val == 'T'", True),
            ("test_var > 'abc'", False),
            ("(test_var == 1) and ((some_val == 'T') or (some_val == 'A'))", False),
        ]

        parser = cp.ConditionParser(parameters)
        for filter_expr, expected in tests:
            parse(filter_expr, expected, parameters, parser)

    def test_conditions_fail_parse(self):
        """Test that the following conditions fail parsing."""
        parameters = {
            'test_var': 100,
            'some_val': 'A',
        }
        tests = [
            # Filter_string, Expected_result)
            ("test_var == xyz", False),
            ("and and", False),
            ("and or", False),
            ("or not", False),
            ("3 or not", False),
            ("not", False),
            ("3 3 3", False),
        ]

        parser = cp.ConditionParser(parameters)
        for filter_expr, expected in tests:
            with self.assertRaises(pyparsing.ParseException):
                parse(filter_expr, expected, parameters, parser)

    def test_conditions_fail_eval(self):
        """Test that the following conditions fail evaluation."""
        parameters = {
            'test_var': 100,
            'some_val': 'A',
        }
        tests = [
            # Filter_string, Expected_result)
            ("test_var == some_val", True),
            ("test_var == -100", True),
            ("some_val < -100", True),
        ]

        parser = cp.ConditionParser(parameters)
        for filter_expr, expected in tests:
            with self.assertRaises(AssertionError):
                parse(filter_expr, expected, parameters, parser)


if __name__ == '__main__':
    unittest.main()
