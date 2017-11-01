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

""" IAMQL grammar definition. """

from pyparsing import Literal
from pyparsing import CaselessLiteral
from pyparsing import Word
from pyparsing import Group
from pyparsing import Optional
from pyparsing import Forward
from pyparsing import nums
from pyparsing import alphas
from pyparsing import Suppress

from sqlalchemy.orm import aliased
from sqlalchemy import and_


class QueryCompiler(object):
    def __init__(self, data_access, session, iam_query):
        self.session = session
        self.iam_query = iam_query
        self.data_access = data_access

    def visit(self, node, transformed_children):
        if isinstance(node, Projection):
            pass
        elif isinstance(node, Selection):
            pass
        elif isinstance(node, Join):
            pass
        else:
            pass

    def compile(self):
        t1 = aliased(self.data_access.TBL_RESOURCE, name='t1')
        t2 = aliased(self.data_access.TBL_RESOURCE, name='t2')
        return (
            self.session.query(t1,
                               t2)
                .filter(
                    and_(t1.full_name.startswith(t2.full_name),
                         t1.full_name != t2.full_name)
                        )
                )


class Node(list):
    def __init__(self, orig, loc, args):
        super(Node, self).__init__(args)
        self.orig = orig
        self.loc = loc

    def __eq__(self, other):
        return (
            self.__class__ == other.__class__ and
            super(Node, self).__eq__(other))

    @classmethod
    def build(cls, e):
        def action(s, l, t):
            try:
                lst = t[0].asList()
            except Exception as e:
                lst = t
            return [cls(s, l, lst)]
        return Group(e).setParseAction(action)

    def __repr__(self):
        return '{}@{}({})'.format(
            self.__class__.__name__,
            self.loc,
            super(Node, self).__repr__())

    def accept(self, visitor):
        new_nodes = []
        for node in self:
            new_nodes.append(node.accept(visitor))
        return visitor.visit(self, new_nodes)


class Selection(Node):
    pass


class Projection(Node):
    pass


class Join(Node):
    pass


class QueryName(Node):
    pass


class Query(Node):
    pass


class QuerySet(Node):
    pass


def BNF():
    """Get the BNF for IAMQL

    Returns:
        object: BNF
    """

    # allowed_joins = [
    #    ('role', 'has', 'permission'),
    #    ('permission', 'includes', 'role'),
    #    ('resource', 'parentOf', 'resource'),
    #    ('resource', 'childOf', 'resource'),
    #    ('resource', 'ancestorOf', 'resource'),
    #    ('resource', 'descendantOf', 'resource'),
    #    ('resource', 'granted', ('role', 'member')),
    #    ('role', 'granted', ('resource', 'member')),
    #    ('member', 'granted', ('resource', 'role')),
    #    ]

    tbl_policy = CaselessLiteral('policy')
    tbl_resource = CaselessLiteral('resource')
    tbl_role = CaselessLiteral('role')
    tbl_permission = CaselessLiteral('permission')
    tbl_member = CaselessLiteral('member')
    tbl_group = CaselessLiteral('group')
    tbl_user = CaselessLiteral('user')

    LPAREN = Suppress('(')
    RPAREN = Suppress(')')
    LBRACE = Suppress('{')
    RBRACE = Suppress('}')
    SEMICOLON = Suppress(';')
    COLON = Suppress(':')
    DOT = Suppress('.')
    COMMA = Suppress(',')
    EQUAL = Literal('==')

    entity = (
        tbl_policy |
        tbl_resource |
        tbl_role |
        tbl_permission |
        tbl_member |
        tbl_group |
        tbl_user)

    number = Word(nums)
    relation = Word(alphas)
    ident = Word(alphas)
    attribute = Word(alphas)
    filterspec = Group(attribute + EQUAL + number)
    arglist = Forward()
    arglist = filterspec + Optional(COMMA + arglist)
    decl = (
        ident + entity +
        Optional(LPAREN + Group(Optional(arglist)) + RPAREN) +
        SEMICOLON
        )

    selection = Forward()
    selection << Group(decl) + Optional(selection)

    entitylist = Forward()
    entitylist << ident + Optional(COMMA + entitylist)

    join = Forward()
    join << (
        Group(ident + DOT + relation +
              LPAREN + Group(entitylist) + RPAREN + SEMICOLON) +
        Optional(join)
        )

    projection = Forward()
    projection << (
        Group(ident) + Optional(COMMA + projection)
        )

    query = (
        QueryName.build(ident) + COLON +
        LBRACE + Selection.build(selection) + RBRACE +
        LBRACE + Join.build(Optional(join)) + RBRACE +
        LBRACE + Projection.build(projection) + RBRACE
        )

    queryset = Forward()
    queryset << Query.build(query) + Optional(queryset)
    bnf = QuerySet.build(queryset)
    return bnf


if __name__ == "__main__":
    """Main test method."""

    def test():
        bnf = BNF()
        results = bnf.parseFile('test.query', parseAll=True)
        print results.dump()
    test()
