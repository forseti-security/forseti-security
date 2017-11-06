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
import pprint

from sqlalchemy.orm import aliased
from sqlalchemy import and_

allowed_joins = {
    'role': [
        ('has',
         ['permission'],
         lambda dao, r, p: (
             and_(dao.TBL_ROLE_PERMISSION.c.roles_name == r.table.name,
                  dao.TBL_ROLE_PERMISSION.c.permissions_name == p.table.name)
             )),
        ],
    'binding': [
        ('grants',
         ['resource', 'role', 'member'],
         lambda dao, binding, resource, role, member: (
             and_(binding.table.resource_type_name == resource.table.type_name,
                  binding.table.role_name == role.table.name,
                  dao.TBL_BINDING_MEMBERS.c.members_name == member.table.name,
                  dao.TBL_BINDING_MEMBERS.c.bindings_id == binding.table.id)
             )),
        ],
    }


class Variable(dict):
    @property
    def entity(self):
        return self['entity']

    @property
    def identifier(self):
        return self['identifier']

    def _get_table(self):
        return self['table']

    def _set_table(self, value):
        self['table'] = value

    def _del_table(self):
        del self['table']

    table = property(_get_table, _set_table, _del_table)


class QueryCompiler(object):
    def __init__(self, data_access, session, iam_query):
        self.session = session
        self.iam_query = iam_query
        self.data_access = data_access

        self.variables = {}
        self.projection = []
        self.joins = []

    def get_table_by_entity(self, entity):
        type_mapping = {
                'resource': self.data_access.TBL_RESOURCE,
                'role': self.data_access.TBL_ROLE,
                'permission': self.data_access.TBL_PERMISSION,
                'binding': self.data_access.TBL_BINDING,
                'member': self.data_access.TBL_MEMBER,
                'role_permission': self.data_access.TBL_ROLE_PERMISSION
            }

        return type_mapping[entity]

    def visit(self, node, transformed_children):
        handlers = {
                EntityDefinition: self.visit_entity_definition,
                Projection: self.visit_projection,
                Join: self.visit_join,
            }
        for base_type, handler in handlers.iteritems():
            if isinstance(node, base_type):
                return handler(node, transformed_children)
        return node

    def visit_entity_definition(self, node, transformed_children):
        ident = node.identifier
        entity = node.entity

        table = aliased(self.get_table_by_entity(entity),
                        name=ident)
        self.variables[ident] = Variable({'identifier': ident,
                                          'entity': entity,
                                          'table': table})

    def visit_projection(self, node, transformed_children):
        self.projection = node.entities

    def visit_join(self, node, transformed_children):
        self.joins.append(node)

    def generate_join_filter(self, join):
        obj = self.variables[join.object]
        obj_type = obj.entity
        for join_spec in allowed_joins[obj_type]:
            relation, arglist, generator = join_spec
            if relation == join.relation:
                for arg_pos, arg_type in enumerate(arglist):
                    var = self.variables[join.arglist[arg_pos]]
                    if var.entity != arg_type:
                        raise TypeError(
                            'Relation: {}, expected: {}, actual: {}'
                            .format(relation, arg_type, ))
                generated = generator(self.data_access,
                                      obj,
                                      *map(lambda ident:
                                           self.variables[ident], join.arglist))
                return generated

        raise Exception('Undefined join relationship: {}'.format(join))

    def compile(self):
        ast = BNF().parseString(self.iam_query, parseAll=True)
        query_set = ast[0]
        query_set.accept(self)

        entities = []
        for identifier in self.projection:
            variable = self.variables[identifier]
            entities.append(variable.table)

        qry = self.session.query(*entities)
        for join in self.joins:
            join_clause = self.generate_join_filter(join)
            qry = qry.filter(join_clause)

        return qry.distinct()


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
            if isinstance(node, Node):
                new_nodes.append(node.accept(visitor))
        return visitor.visit(self, new_nodes)


class Selection(Node):
    pass


class Projection(Node):
    @property
    def entities(self):
        return [item for sublist in self for item in sublist]


class JoinList(Node):
    pass


class Join(Node):
    @property
    def object(self):
        return self[0]

    @property
    def relation(self):
        return self[1]

    @property
    def arglist(self):
        return self[2]


class Query(Node):
    @property
    def name(self):
        return self[0]

    @property
    def declarations(self):
        pass


class QueryName(Node):
    def __str__(self):
        return self[0]


class QuerySet(Node):
    pass


class EntityDefinition(Node):
    @property
    def identifier(self):
        return self[0]

    @property
    def entity(self):
        return self[1]


class EntityFilter(Node):
    pass


def BNF():
    """Get the BNF for IAMQL

    Returns:
        object: BNF
    """

    tbl_policy = CaselessLiteral('policy')
    tbl_resource = CaselessLiteral('resource')
    tbl_role = CaselessLiteral('role')
    tbl_permission = CaselessLiteral('permission')
    tbl_member = CaselessLiteral('member')
    tbl_group = CaselessLiteral('group')
    tbl_user = CaselessLiteral('user')
    tbl_binding = CaselessLiteral('binding')

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
        tbl_user |
        tbl_binding)

    number = Word(nums)
    relation = Word(alphas)
    ident = Word(alphas)
    attribute = Word(alphas)
    filterspec = Group(attribute + EQUAL + number)
    arglist = Forward()
    arglist = filterspec + Optional(COMMA + arglist)
    decl = (
        ident + entity +
        Optional(LPAREN + EntityFilter.build(Optional(arglist)) + RPAREN) +
        SEMICOLON
        )

    selection = Forward()
    selection << EntityDefinition.build(decl) + Optional(selection)

    entitylist = Forward()
    entitylist << ident + Optional(COMMA + entitylist)

    join = Forward()
    join << (
        Join.build(ident + DOT + relation +
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
        LBRACE + JoinList.build(Optional(join)) + RBRACE +
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
        ast = bnf.parseFile('test.query', parseAll=True)
        pprint.pprint(ast)

    test()
