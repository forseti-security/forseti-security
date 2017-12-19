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

"""IAMQL compiler implementation."""

from sqlalchemy.orm import aliased
from sqlalchemy import and_, not_, or_

from google.cloud.forseti.services.iamql.ast import *
from google.cloud.forseti.services.iamql.relations import Metadata
from google.cloud.forseti.services.iamql.grammar import BNF


class Variable(dict):
    """Stores variables in scope."""

    @property
    def entity(self):
        """Access the entity (type).

        Returns:
            str: type of the entity.
        """
        return self['entity']

    @property
    def identifier(self):
        """Access the variable identifier.

        Returns:
            str: identifier.
        """
        return self['identifier']

    def _get_table(self):
        """Access the table object corresponding the type.

        Returns:
            object: Table object.
        """
        return self['table']

    def _set_table(self, value):
        """Set the table object corresponding the type.

        Args:
            value (object): Table object.
        """
        self['table'] = value

    def _del_table(self):
        """Remove the table object from the variable."""
        del self['table']

    """Get/Set/Del for table property."""
    table = property(_get_table, _set_table, _del_table)


class QueryContext(object):
    """Holds the state of a query while compiling."""

    def __init__(self, compilation_context, query_node):
        self._variables = {}

    @property
    def variables(self):
        """Access to variable definitions.

        Returns:
            dict: Variables keyed by name.
        """
        return self._variables


class CompilationContext(object):
    """Traverses the AST and creates the compilation artefacts.

    The purpose is to have the AST node definitions
    separate from the 'code generation' part.
    """

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

    def on_enter_entity_definition(self, node):
        ident = node.identifier
        entity = node.entity

        table_class_func, constraint_func = Metadata.type_mapping[entity]
        table = aliased(table_class_func(self.data_access),
                        name=ident)
        if constraint_func is not None:
            self.conditions.append(constraint_func(table))
        self.variables[ident] = Variable({'identifier': ident,
                                          'entity': entity,
                                          'table': table})

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
                Projection: self.on_enter_projection,
                EntityDefinition: self.on_enter_entity_definition,
            }
        self._exec_matching_handler(handlers, node)

    def leave(self, node, artefacts):
        handlers = {
                UnsafeJoin: self.on_leave_unsafe_join,
                UnsafeJoinTarget: self.on_leave_unsafe_jointarget,
                Query: self.on_leave_query,
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
    """Main compiler front-end."""

    def __init__(self, data_access, session, iam_query):
        self.session = session
        self.iam_query = iam_query
        self.data_access = data_access

        self.variables = {}
        self.projection = []
        self.joins = []
        self.last_defined_variable = None

    def compile(self):
        """Compiles the member iam_query into a sql query.

        Returns:
            object: Compiled query.
        """
        ast = BNF().parseString(self.iam_query, parseAll=True)
        query_set = ast[0]

        context = CompilationContext(self.data_access,
                                     Metadata.entity_attributes,
                                     Metadata.allowed_joins,
                                     self.session)

        artefact = query_set.compile(context)
        return artefact
