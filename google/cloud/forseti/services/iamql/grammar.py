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

"""IAMQL grammar."""

from pyparsing import Literal
from pyparsing import CaselessLiteral
from pyparsing import Word
from pyparsing import Optional
from pyparsing import Forward
from pyparsing import nums
from pyparsing import alphas
from pyparsing import alphanums
from pyparsing import dblQuotedString
from pyparsing import Suppress
from pyparsing import Keyword

import google.cloud.forseti.services.iamql.ast as ast


def BNF():
    """Get the BNF for IAMQL

    Returns:
        object: BNF
    """

    tbl_resource = CaselessLiteral('resource')
    tbl_role = CaselessLiteral('role')
    tbl_permission = CaselessLiteral('permission')
    tbl_member = CaselessLiteral('member')
    tbl_group = CaselessLiteral('group')
    tbl_user = CaselessLiteral('user')
    tbl_binding = CaselessLiteral('binding')
    tbl_serviceaccount = CaselessLiteral('serviceaccount')

    LPAREN = Suppress('(')
    RPAREN = Suppress(')')
    LBRACE = Suppress('{')
    RBRACE = Suppress('}')
    SEMICOLON = Suppress(';')
    COLON = Suppress(':')
    DOT = Suppress('.')
    COMMA = Suppress(',')
    LBRACK = Suppress('[')
    RBRACK = Suppress(']')

    EQ = Literal('==')
    NEQ = Literal('!=')
    GT = Literal('>')
    LT = Literal('<')
    LTE = Literal('<=')
    GTE = Literal('>=')

    AND = Keyword('and')
    OR = Keyword('or')
    NOT = Keyword('not')
    IN = Keyword('in')
    LIKE = Keyword('like')

    entity = (
        tbl_resource |
        tbl_role |
        tbl_permission |
        tbl_member |
        tbl_group |
        tbl_user |
        tbl_binding |
        tbl_serviceaccount)

    string = dblQuotedString
    number = Word(nums)
    relation = Word(alphas)
    ident = Word(alphanums)
    attribute_ident = Word(alphas + '_')
    attribute_ref = ast.AttributeRef.build(attribute_ident)
    attribute = ast.Attribute.build(attribute_ident)

    comparator = EQ | NEQ | GT | LT | LTE | GTE
    literal = ast.Number.build(number) | ast.String.build(string)

    literal_list_item = Forward()
    literal_list_item << literal + Optional(COMMA + literal_list_item)
    literal_list = ast.LiteralList.build(LBRACK + literal_list_item + RBRACK)

    comparison = (
        ast.LikeOperator.build(attribute +
                               Suppress(LIKE) +
                               ast.String.build(string)) |
        ast.InOperator.build(attribute + IN + literal_list) |
        ast.Comparison.build(attribute + comparator + literal) |
        ast.Comparison.build(literal + comparator + attribute)
        )

    entityfilter = Forward()
    entityfilter << (
        comparison |
        ast.Not.build(NOT + LPAREN + entityfilter + RPAREN) |
        ast.And.build(LPAREN + entityfilter + RPAREN +
                      AND +
                      LPAREN + entityfilter + RPAREN) |
        ast.Or.build(LPAREN + entityfilter + RPAREN +
                     OR +
                     LPAREN + entityfilter + RPAREN) |
        ast.Paren.build(LPAREN + entityfilter + RPAREN)
        )

    decl = (
        ident + entity +
        Optional(LPAREN +
                 ast.EntityFilter.build(entityfilter) +
                 RPAREN) +
        SEMICOLON
        )

    selection = Forward()
    selection << ast.EntityDefinition.build(decl) + Optional(selection)

    entitylist = Forward()
    entitylist << ident + Optional(COMMA + entitylist)

    join = Forward()
    join << (
        (ast.SafeJoin.build(
            ident + DOT + relation + LPAREN +
            ast.Group(entitylist) + RPAREN)
         |
         ast.UnsafeJoin.build(
             ast.UnsafeJoinTarget.build(ident + DOT + attribute_ref)
             + Suppress(EQ) +
             ast.UnsafeJoinTarget.build(ident + DOT + attribute_ref))
         ) +
        SEMICOLON +
        Optional(join)
        )

    projection = Forward()
    projection << (
        ast.Group(ident) + Optional(COMMA + projection)
        )

    query = (
        ast.QueryName.build(ident) + COLON +
        LBRACE + ast.Selection.build(selection) + RBRACE +
        LBRACE + ast.JoinList.build(Optional(join)) + RBRACE +
        LBRACE + ast.Projection.build(projection) + RBRACE
        )

    queryset = Forward()
    queryset << ast.Query.build(query) + Optional(queryset)
    bnf = ast.QuerySet.build(queryset)
    return bnf
