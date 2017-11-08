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

"""Parser for simple Python expressions to reduce to boolean.

From https://gist.github.com/cynici/5865326
"""

import logging

import pyparsing


pyparsing.ParserElement.enablePackrat()


# pylint: disable=invalid-name
# pylint: disable=missing-param-doc
# pylint: disable=missing-return-doc
# pylint: disable=missing-return-type-doc
# pylint: disable=missing-type-doc
# pylint: disable=missing-yield-doc
# pylint: disable=missing-yield-type-doc
# pylint: disable=unused-argument
def eval_sign_op(s, l, t):
    """Evaluate expressions with a leading + or - sign"""
    sign, value = t[0]
    mult = {'+':1, '-':-1}[sign]
    res = mult * value
    logging.debug("SIGN: t=%s res=%s", t, res)
    return res

def _operator_operands(tokenlist):
    """Generator to extract operators and operands in pairs"""
    it = iter(tokenlist)
    while 1:
        try:
            o1 = next(it)
            o2 = next(it)
            yield (o1, o2)
        except StopIteration:
            break

def eval_mult_op(s, l, t):
    """Evaluate multiplication and division expressions"""
    prod = t[0][0]
    for op, val in _operator_operands(t[0][1:]):
        if op == '*':
            prod *= val
        if op == '/':
            prod /= val
        if op == '//':
            prod //= val
        if op == '%':
            prod %= val
    logging.debug("MULT: t=%s res=%s", t, prod)
    return prod

def eval_add_op(s, l, t):
    """Evaluate addition and subtraction expressions"""
    total = t[0][0]
    for op, val in _operator_operands(t[0][1:]):
        if op == '+':
            total += val
        if op == '-':
            total -= val
    logging.debug("ADD: t=%s res=%s", t, total)
    return total

def eval_comparison_op(s, l, t):
    """Evaluate comparison expressions"""
    opMap = {
        "<": lambda a, b: a < b,
        "<=": lambda a, b: a <= b,
        ">": lambda a, b: a > b,
        ">=": lambda a, b: a >= b,
        "==": lambda a, b: a == b,
        "!=": lambda a, b: a != b,
        }
    res = False
    val1 = t[0][0]
    for op, val2 in _operator_operands(t[0][1:]):
        fn = opMap[op]
        if not fn(val1, val2):
            break
        val1 = val2
    else:
        res = True
    logging.debug("COMP: t=%s res=%s\n", t, res)
    return res

def eval_and(s, l, t):
    """Evaluate `and` expression."""
    bool1, op, bool2 = t[0]
    res = bool1 and bool2
    logging.debug("%s %s %s res=%s", bool1, op, bool2, res)
    return res

def eval_or(s, l, t):
    """Evaluate `or` expression."""
    bool1, op, bool2 = t[0]
    res = bool1 or bool2
    logging.debug("%s %s %s res=%s", bool1, op, bool2, res)
    return res

def eval_not(s, l, t):
    """Evaluate `not` expression."""
    op, bool1 = t[0]
    res = not bool1
    logging.debug("%s %s res=%s", op, bool1, res)
    return res

# pylint: enable=missing-param-doc
# pylint: enable=missing-return-doc
# pylint: enable=missing-return-type-doc
# pylint: enable=missing-type-doc
# pylint: enable=missing-yield-doc
# pylint: enable=missing-yield-type-doc


class ConditionParser(object):
    """Parser class."""

    Param = pyparsing.Word(pyparsing.alphas+"_", pyparsing.alphanums+"_")
    Qstring = pyparsing.quotedString(r".*").setParseAction(
        pyparsing.removeQuotes)
    PosInt = pyparsing.Word(pyparsing.nums).setParseAction(
        lambda s, l, t: [int(t[0])])
    PosReal = (
        pyparsing.Combine(
            pyparsing.Word(pyparsing.nums) +
            pyparsing.Optional("." + pyparsing.Word(pyparsing.nums)) +
            pyparsing.oneOf("E e") +
            pyparsing.Optional(pyparsing.oneOf('+ -')) +
            pyparsing.Word(pyparsing.nums)) |
        pyparsing.Combine(
            pyparsing.Word(pyparsing.nums) + "." +
            pyparsing.Word(pyparsing.nums))
        ).setParseAction(lambda s, l, t: [float(t[0])])

    signop = pyparsing.oneOf('+ -')
    multop = pyparsing.oneOf('* / // %')
    plusop = pyparsing.oneOf('+ -')
    comparisonop = pyparsing.oneOf("< <= > >= == !=")

    andop = pyparsing.CaselessKeyword("AND")
    orop = pyparsing.CaselessKeyword("OR")
    notop = pyparsing.CaselessKeyword("NOT")

    def __init__(self, param_dic=None):
        """Initialize.

        Args:
            param_dic (dict): The parameter dictionary.

        Raises:
            ValueError: If there is a parameter collision.
        """
        if param_dic is None:
            param_dic = {}
        self.param_dic = {}
        # Save parameters (key-value pairs), but with capitalized key
        for key, val in param_dic.items():
            upper_key = key.upper()
            if upper_key in self.param_dic:
                raise ValueError("Parameter key collision: '%s'" % key)
            self.param_dic[upper_key] = val

    def set_param(self, orig_str, loc, tokens):
        """Replace keywords with actual values using param_dic mapping.

        Args:
            orig_str (str): The original string to be parsed.
            loc (str): The location of the matching substring.
            tokens (list): The list of matched tokens.

        Returns:
            str: The found param.

        Raises:
            ParseException: If there is an undefined variable in
                the expression.
        """
        del orig_str
        del loc
        param = tokens[0].upper()
        found_param = self.param_dic.get(param)
        if not found_param:
            raise pyparsing.ParseException('Undefined variable: %s' % (param))
        return found_param

    def eval_filter(self, filter_expr):
        """Evaluate the expression.

        Args:
            filter_expr (str): The expression string to evaluate.

        Returns:
            bool: True if the expression evaluates to True, otherwise False.
        """
        keyword = self.Param.copy()
        atom = (self.PosReal |
                self.PosInt |
                self.Qstring |
                keyword.setParseAction(self.set_param))
        expr = pyparsing.infixNotation(atom, [
            (self.signop, 1, pyparsing.opAssoc.RIGHT, eval_sign_op),
            (self.multop, 2, pyparsing.opAssoc.LEFT, eval_mult_op),
            (self.plusop, 2, pyparsing.opAssoc.LEFT, eval_add_op),
            (self.comparisonop, 2, pyparsing.opAssoc.LEFT, eval_comparison_op),
            (self.notop, 1, pyparsing.opAssoc.RIGHT, eval_not),
            (self.andop, 2, pyparsing.opAssoc.LEFT, eval_and),
            (self.orop, 2, pyparsing.opAssoc.LEFT, eval_or),
        ])
        return expr.parseString(filter_expr, parseAll=True)[0]


def parse(filter_expr, expected, params, parser=ConditionParser):
    """Parse the expression.

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

    logging.debug('\nexpr: %s, expected: %s', filter_expr, expected)

    result = parser.eval_filter(filter_expr)
    if result != expected:
        raise AssertionError("yields %s instead of %s" % (result, expected))
    logging.debug('Parsed successfully')
