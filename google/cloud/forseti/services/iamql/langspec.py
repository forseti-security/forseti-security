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

""" IAMQL grammar & compiler implementation. """

import pprint

from pyparsing import Literal
from pyparsing import CaselessLiteral
from pyparsing import Word
from pyparsing import Group
from pyparsing import Optional
from pyparsing import Forward
from pyparsing import nums
from pyparsing import alphas
from pyparsing import alphanums
from pyparsing import dblQuotedString
from pyparsing import Suppress
from pyparsing import Keyword

from sqlalchemy.orm import aliased
from sqlalchemy import and_, not_, or_
from sqlalchemy.dialects import mysql


class Metadata(object):
    entity_attributes = {
        'resource': {
            'path': {
                'type': unicode,
                },
            'type': {
                'type': unicode,
                },
            'name': {
                'type': unicode,
                },
            'display_name': {
                'type': unicode,
                },
            'email': {
                'type': unicode,
                },
            },
        'role': {
            'name': {
                'type': unicode,
                },
            'title': {
                'type': unicode,
                },
            'description': {
                'type': unicode,
                },
            },
        'permission': {
            'name': {
                'type': unicode,
                },
            },
        'member': {
            'name': {
                'type': unicode,
                },
            'type': {
                'type': unicode,
                },
            },
        'group': {
            'name': {
                'type': unicode,
                },
            'type': {
                'type': unicode,
                },
            },
        'user': {
            'name': {
                'type': unicode,
                },
            'type': {
                'type': unicode,
                },
            },
        'serviceaccount': {
            'name': {
                'type': unicode,
                },
            'type': {
                'type': unicode,
                },
            },
        'binding': {},
        }

    allowed_joins = {
        'group': [
            ('contains',
             [['group', 'member', 'user', 'serviceaccount']],
             lambda dao, parent, child: (
                 and_(
                  dao.TBL_MEMBERSHIP.c.group_name == parent.table.name,
                  dao.TBL_MEMBERSHIP.c.members_name == child.table.name)
                 )),
            ('transitivecontains',
             [['member', 'user', 'serviceaccount']],
             lambda dao, parent, child: (
                 and_(
                  dao.TBL_GROUP_IN_GROUP.parent == parent.table.name,
                  dao.TBL_GROUP_IN_GROUP.member == dao.TBL_MEMBERSHIP.c.group_name,
                  dao.TBL_MEMBERSHIP.c.members_name == child.table.name)
                 )),
            ('transitivecontains',
             ['group'],
             lambda dao, parent, child: (
                 and_(
                  dao.TBL_GROUP_IN_GROUP.parent == parent.table.member,
                  dao.TBL_GROUP_IN_GROUP.member == child.table.member),
                 )),
            ],
        'member': [
            ('contains',
             [['group', 'member', 'user', 'serviceaccount']],
             lambda dao, parent, child: (
                 and_(
                  dao.TBL_MEMBERSHIP.c.group_name == parent.table.name,
                  dao.TBL_MEMBERSHIP.c.members_name == child.table.name)
                 )),
            ('transitivecontains',
             [['member', 'user', 'serviceaccount']],
             lambda dao, parent, child: (
                 and_(
                  dao.TBL_GROUP_IN_GROUP.parent == parent.table.name,
                  dao.TBL_GROUP_IN_GROUP.member == dao.TBL_MEMBERSHIP.c.group_name,
                  dao.TBL_MEMBERSHIP.c.members_name == child.table.name)
                 )),
            ('transitivecontains',
             ['group'],
             lambda dao, parent, child: (
                 and_(
                  dao.TBL_GROUP_IN_GROUP.parent == parent.table.member,
                  dao.TBL_GROUP_IN_GROUP.member == child.table.member),
                 )),
            ],
        'role': [
            ('has',
             ['permission'],
             lambda dao, r, p: (
                 and_(
                    dao.TBL_ROLE_PERMISSION.c.roles_name == r.table.name,
                    dao.TBL_ROLE_PERMISSION.c.permissions_name == p.table.name)
                 )),
            ],
        'binding': [
            ('grants',
             ['resource', 'role', ['member',
                                   'user',
                                   'group',
                                   'serviceaccount']],
             lambda dao, binding, resource, role, member: (
                 and_(
                  binding.table.resource_type_name == resource.table.type_name,
                  binding.table.role_name == role.table.name,
                  dao.TBL_BINDING_MEMBERS.c.members_name == member.table.name,
                  dao.TBL_BINDING_MEMBERS.c.bindings_id == binding.table.id)
                 )),
            ],
        'permission': [
            ('included',
             ['role'],
             lambda dao, p, r: (
                 and_(
                    dao.TBL_ROLE_PERMISSION.c.roles_name == r.table.name,
                    dao.TBL_ROLE_PERMISSION.c.permissions_name == p.table.name)
                 )),
            ],
        'resource': [
            ('child',
             ['resource'],
             lambda dao, child, parent: (
                 and_(child.table.parent_type_name == parent.table.type_name)
                 )),
            ('parent',
             ['resource'],
             lambda dao, parent, child: (
                 and_(child.table.parent_type_name == parent.table.type_name)
                 )),
            ('ancestor',
             ['resource'],
             lambda dao, ancestor, descendant: (
                 and_(
                     descendant.table.full_name.startswith(
                         ancestor.table.full_name),
                     ancestor.table.type_name != descendant.table.type_name)
                 )),

            ('ancestorWithSelf',
             ['resource'],
             lambda dao, ancestor, descendant: (
                 descendant.table.full_name.startswith(
                     ancestor.table.full_name)
                 )),

            ('descendant',
             ['resource'],
             lambda dao, descendant, ancestor: (
                 and_(
                     descendant.table.full_name.startswith(
                         ancestor.table.full_name),
                     ancestor.table.type_name != descendant.table.type_name)
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


class QueryContext(object):
    def __init__(self, compilation_context, query_node):
        self._variables = {}

    @property
    def variables(self):
        return self._variables


class CompilationContext(object):

    def __init__(self, data_access, entity_attributes, allowed_joins, session):
        self.entity_attributes = entity_attributes
        self.allowed_joins = allowed_joins
        self.session = session

        self.data_access = data_access

        self.queries = {}
        self.cur_query = None
        self.variables = {}
        self.entities = []
        self.join_clauses = []
        self.conditions = []
        self.artefact = None

    def get_table_by_entity(self, entity):
        type_mapping = {
                'resource': (
                    self.data_access.TBL_RESOURCE,
                    None),
                'role': (
                    self.data_access.TBL_ROLE,
                    None),
                'permission': (
                    self.data_access.TBL_PERMISSION,
                    None),
                'binding': (
                    self.data_access.TBL_BINDING,
                    None),
                'member': (
                    self.data_access.TBL_MEMBER,
                    lambda t: t.type.in_(self.data_access.TBL_MEMBER.CORE_TYPES)),
                'group': (
                    self.data_access.TBL_MEMBER,
                    lambda t: t.type == 'group'),
                'user': (
                    self.data_access.TBL_MEMBER,
                    lambda t: t.type == 'user'),
                'serviceaccount': (
                    self.data_access.TBL_MEMBER,
                    lambda t: t.type == 'serviceAccount')
            }

        return type_mapping[entity]

    def on_enter_query(self, query):
        pass

    def on_leave_query(self, query, artefacts):
        qry = self.session.query(*self.entities)
        for clause in self.join_clauses:
            qry = qry.filter(clause)
        for condition in self.conditions:
            qry = qry.filter(condition)
        self.artefact = qry.distinct()

    def on_enter_projection(self, projection):
        for identifier in projection.entities:
            variable = self.variables[identifier]
            self.entities.append(variable.table)

    def on_leave_projection(self, projection, artefacts):
        pass

    def on_enter_entity_definition(self, node):
        ident = node.identifier
        entity = node.entity

        table_class, constraint_func = self.get_table_by_entity(entity)
        table = aliased(table_class,
                        name=ident)
        if constraint_func is not None:
            self.conditions.append(constraint_func(table))
        self.variables[ident] = Variable({'identifier': ident,
                                          'entity': entity,
                                          'table': table})

    def on_leave_entity_definition(self, entity_definition, artefacts):
        pass

    def on_enter_selection(self, selection):
        pass

    def on_leave_selection(self, selection, artefacts):
        pass

    def on_enter_join(self, join):
        obj = self.variables[join.object]
        obj_type = obj.entity
        for join_spec in self.allowed_joins[obj_type]:
            relation, arglist, generator = join_spec
            if relation == join.relation:
                for arg_pos, arg_type in enumerate(arglist):
                    var = self.variables[join.arglist[arg_pos]]
                    if isinstance(arg_type, list):
                        if var.entity not in arg_type:
                            raise TypeError(
                                'Relation: {}, expected: {}, actual: {}'
                                .format(relation, arg_type, var.entity))
                    else:
                        if var.entity != arg_type:
                            raise TypeError(
                                'Relation: {}, expected: {}, actual: {}'
                                .format(relation, arg_type, var.entity))

                self.join_clauses.append(
                    generator(self.data_access,
                              obj,
                              *map(lambda ident:
                                   self.variables[ident], join.arglist)))
                return
        raise Exception('Undefined join relationship: {}'.format(join))

    def on_leave_join(self, join, artefacts):
        pass

    def on_leave_unsafe_join(self, join, artefacts):
        self.conditions.append(artefacts[0] == artefacts[1])

    def on_leave_unsafe_jointarget(self, target, artefacts):
        variable = self.variables[target.name]
        attribute_ref = target.attribute
        return getattr(variable['table'], attribute_ref.name)

    def on_leave_comparison(self, comparison, artefacts):
        if isinstance(comparison.right, Attribute):
            attribute = artefacts[1]
            literal = artefacts[0]
        elif isinstance(comparison.left, Attribute):
            attribute = artefacts[0]
            literal = artefacts[1]
        else:
            raise Exception('Comparison missing an attribute operand')

        operation = comparison.op
        op_functions = {
                '==': attribute.__eq__,
                '!=': attribute.__ne__,
                '>': attribute.__gt__,
                '<': attribute.__lt__,
                '<=': attribute.__le__,
                '>=': attribute.__ge__,
            }
        return op_functions[operation](literal)

    def on_leave_attribute(self, attribute, artefacts):
        variable = self.variables[attribute.entity_def.identifier]
        return getattr(variable['table'], attribute.name)

    def on_leave_scalar(self, scalar, artefacts):
        return scalar.value

    def on_leave_entityfilter(self, entity_filter, artefacts):
        for artefact in artefacts:
            self.conditions.append(artefact)

    def on_leave_not(self, operator, artefacts):
        return not_(*artefacts)

    def on_leave_and(self, operator, artefacts):
        return and_(*artefacts)

    def on_leave_or(self, operator, artefacts):
        return or_(*artefacts)

    def on_leave_in(self, operator, artefacts):
        attribute = artefacts[0]
        literal_list = artefacts[1]
        return attribute.in_(literal_list)

    def on_leave_like(self, operator, artefacts):
        attribute = artefacts[0]
        return attribute.like(operator.literal.value)

    def enter(self, node):
        handlers = {
                SafeJoin: self.on_enter_join,
                Query: self.on_enter_query,
                Projection: self.on_enter_projection,
                Selection: self.on_enter_selection,
                EntityDefinition: self.on_enter_entity_definition,
            }
        self._exec_matching_handler(handlers, node)

    def leave(self, node, artefacts):
        handlers = {
                SafeJoin: self.on_leave_join,
                UnsafeJoin: self.on_leave_unsafe_join,
                UnsafeJoinTarget: self.on_leave_unsafe_jointarget,
                Query: self.on_leave_query,
                Projection: self.on_leave_projection,
                Selection: self.on_leave_selection,
                EntityDefinition: self.on_leave_entity_definition,
                Comparison: self.on_leave_comparison,
                Attribute: self.on_leave_attribute,
                Scalar: self.on_leave_scalar,
                EntityFilter: self.on_leave_entityfilter,
                Not: self.on_leave_not,
                And: self.on_leave_and,
                Or: self.on_leave_or,
                LikeOperator: self.on_leave_like,
                InOperator: self.on_leave_in,
            }
        return self._exec_matching_handler(handlers, node, artefacts)

    def _exec_matching_handler(self, handlers, node, artefacts=None):
        for cls, handler in handlers.iteritems():
            if isinstance(node, cls):
                if artefacts is not None:
                    return handler(node, artefacts)
                else:
                    return handler(node)
        return artefacts


class QueryCompiler(object):
    def __init__(self, data_access, session, iam_query):
        self.session = session
        self.iam_query = iam_query
        self.data_access = data_access

        self.variables = {}
        self.projection = []
        self.joins = []
        self.last_defined_variable = None

    def compile(self):
        ast = BNF().parseString(self.iam_query, parseAll=True)
        query_set = ast[0]

        context = CompilationContext(self.data_access,
                                     Metadata.entity_attributes,
                                     Metadata.allowed_joins,
                                     self.session)

        artefact = query_set.compile(context)
        self.print_query(artefact)
        return artefact

    def print_query(self, artefact):
        print self.artefact.statement.compile(
            dialect=mysql.dialect(),
            compile_kwargs={"literal_binds": True})


class Node(list):
    def __init__(self, orig, loc, args):
        super(Node, self).__init__(args)
        self.orig = orig
        self.loc = loc

        self._connected = False
        self._parent = None

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
        if not self._connected:
            self._connect()
        new_nodes = []
        for node in self:
            if isinstance(node, Node):
                new_nodes.append(node.accept(visitor))
        return visitor.visit(self, new_nodes)

    def _connect(self, parent=None):
        if not self._connected:
            self._connected = True
            self._parent = parent

            for item in self:
                if isinstance(item, Node):
                    item._connect(self)

    def _find_ancestor(self, cls):
        if not self._parent:
            return None
        elif isinstance(self, cls):
            return self
        return self._parent._find_ancestor(cls)

    def typecheck(self):
        return []

    def compile(self, context):
        if not self._connected:
            self._connect()

        context.enter(self)
        artefacts = []
        for item in self:
            if isinstance(item, Node):
                artefacts.append(item.compile(context))
        return context.leave(self, artefacts)


class QuerySet(Node):
    def compile(self, context):
        Node.compile(self, context)
        return context.artefact


class Selection(Node):
    pass


class Projection(Node):
    @property
    def entities(self):
        return [item for sublist in self for item in sublist]


class JoinList(Node):
    pass


class SafeJoin(Node):
    @property
    def object(self):
        return self[0]

    @property
    def relation(self):
        return self[1]

    @property
    def arglist(self):
        return self[2]


class UnsafeJoinTarget(Node):
    @property
    def name(self):
        return self[0]

    @property
    def attribute(self):
        return self[1]

    def type_of(self):
        return self.attribute.type_of()


class UnsafeJoin(Node):
    @property
    def src(self):
        return self[0]

    @property
    def dst(self):
        return self[1]

    def typecheck(self):
        if self.src.type_of() != self.dst.type_of():
            raise TypeError('type({}) != type({})'.format(self.src,
                                                          self.dst))


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

    def __hash__(self):
        return self[0].__hash__()


class EntityDefinition(Node):
    @property
    def identifier(self):
        return self[0]

    @property
    def entity(self):
        return self[1]


class EntityFilter(Node):
    pass


class Not(Node):
    pass


class Paren(Node):
    pass


class Attribute(Node):
    def __init__(self, *args, **kwargs):
        super(Attribute, self).__init__(*args, **kwargs)
        self.attribute_type = None

    @property
    def name(self):
        return self[0]

    @property
    def entity_def(self):
        entity_def = self._find_ancestor(EntityDefinition)
        if entity_def is None:
            raise Exception('Unable to find ancestor node')
        return entity_def

    def _find_entity_def(self):
        return self._find_ancestor(EntityDefinition)

    def typecheck(self):
        entity = self.entity_def.entity
        self.attribute_type = (
            Metadata.entity_attributes[entity][self.name]['type'])
        return self.attribute_type

    def type_of(self):
        return (self.attribute_type
                if self.attribute_type
                else self.typecheck())


class AttributeRef(Node):
    @property
    def name(self):
        return self[0]

    def type_of(self):
        return None


class Operator(Node):
    def __init__(self, *args, **kwargs):
        super(Operator, self).__init__(*args, **kwargs)

    @property
    def op(self):
        return self[1]

    @property
    def right(self):
        return self[2]

    @property
    def left(self):
        return self[0]

    def typecheck(self):
        try:
            self.left.typecheck()
            self.right.typecheck()
        except Exception:
            raise

        if self.right.type_of() != self.left.type_of():
            raise TypeError('type({}) != type({})'.format(self.left,
                                                          self.right))


class And(Operator):
    pass


class Or(Operator):
    pass


class Scalar(Node):
    def typecheck(self):
        pass


class String(Scalar):
    @property
    def value(self):
        return self[0][1:-1]

    def type_of(self):
        return unicode


class Number(Scalar):
    @property
    def value(self):
        return self[0]

    def type_of(self):
        return int


class Comparison(Operator):
    pass


class InOperator(Node):
    pass


class LikeOperator(Operator):
    @property
    def literal(self):
        return self[1]


class LiteralList(Node):
    @property
    def value(self):
        return [x.value for x in self]

    def typecheck(self):
        t = self.type_of()
        for item in self:
            item_type = item.type_of()
            if t != item_type:
                raise TypeError(
                    'list type: {}, item type: {}'.format(
                        t, item_type))

    def type_of(self):
        return [self[0].type_of()]


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
    DOUBLE_QUOTE = Suppress('"')
    LBRACK = Suppress('[')
    RBRACK = Suppress(']')

    UNDERSCORE = '_'

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
    attribute_ref = AttributeRef.build(attribute_ident)
    attribute = Attribute.build(attribute_ident)

    comparator = EQ | NEQ | GT | LT | LTE | GTE
    literal = Number.build(number) | String.build(string)

    literal_list_item = Forward()
    literal_list_item << literal + Optional(COMMA + literal_list_item)
    literal_list = LiteralList.build(LBRACK + literal_list_item + RBRACK)

    comparison = (
        LikeOperator.build(attribute + Suppress(LIKE) + String.build(string)) |
        InOperator.build(attribute + IN + literal_list) |
        Comparison.build(attribute + comparator + literal) |
        Comparison.build(literal + comparator + attribute)
        )

    entityfilter = Forward()
    entityfilter << (
        comparison |
        Not.build(NOT + LPAREN + entityfilter + RPAREN) |
        And.build(LPAREN + entityfilter + RPAREN + AND + LPAREN + entityfilter + RPAREN) |
        Or.build(LPAREN + entityfilter + RPAREN + OR + LPAREN + entityfilter + RPAREN) |
        Paren.build(LPAREN + entityfilter + RPAREN)
        )

    decl = (
        ident + entity +
        Optional(LPAREN +
                 EntityFilter.build(entityfilter) +
                 RPAREN) +
        SEMICOLON
        )

    selection = Forward()
    selection << EntityDefinition.build(decl) + Optional(selection)

    entitylist = Forward()
    entitylist << ident + Optional(COMMA + entitylist)

    join = Forward()
    join << (
        (SafeJoin.build(
            ident + DOT + relation + LPAREN +
            Group(entitylist) + RPAREN)
         |
         UnsafeJoin.build(
             UnsafeJoinTarget.build(ident + DOT + attribute_ref)
             + Suppress(EQ) +
             UnsafeJoinTarget.build(ident + DOT + attribute_ref))
         ) +
        SEMICOLON +
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
        query_set = ast[0]
        query_set.typecheck()

    test()
