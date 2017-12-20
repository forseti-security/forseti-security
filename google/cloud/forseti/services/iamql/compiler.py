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

"""IAMQL compiler implementation"""

from sqlalchemy.orm import aliased
from sqlalchemy import and_, not_, or_

from google.cloud.forseti.services.iamql import ast
from google.cloud.forseti.services.iamql.relations import Metadata
from google.cloud.forseti.services.iamql.grammar import BNF

# pylint: disable=unused-argument,too-many-instance-attributes
# pylint: disable=bad-builtin,deprecated-lambda,no-self-use


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

    table = property(_get_table, _set_table, _del_table)


class QueryContext(object):
    """Holds the state of a query while compiling."""

    def __init__(self, compilation_context, query_node):
        """Constructor
        Args:
            compilation_context (object): Currently unused.
            query_node (object): Currently unused.
        """
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
        """Constructor
        Args:
            data_access (object): Data access object
            entity_attributes (dict): Entity attribute name/type dict
            allowed_joins (dict): Join relationships
            session (object): Database session
        """
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
        """Creates the compiled artifact for a single query
        Args:
            query (object): Query AST node
            artefacts (list): omitted
        """
        qry = self.session.query(*self.entities)
        for clause in self.join_clauses:
            qry = qry.filter(clause)
        for condition in self.conditions:
            qry = qry.filter(condition)
        self.artefact = qry.distinct()

    def on_enter_projection(self, projection):
        """Perform lookup on the variables and add the
        corresponding table entities to the query list

        Args:
            projection (ast.Projection): Projection AST node
        """
        for identifier in projection.entities:
            variable = self.variables[identifier]
            self.entities.append(variable.table)

    def on_enter_entity_definition(self, node):
        """Define the required variable for the definition
        and apply a condition in case the entity is by only
        referring to a subset of an actual database table.

        For example, serviceaccounts is derived from member
        with the condition "type == serviceAccount".

        Args:
            node (ast.EntityDefinition): EntityDefinition AST node
        """
        ident = node.identifier
        entity = node.entity

        table_class_func, constraint_func = Metadata.type_mapping[entity]
        table = aliased(table_class_func(self.data_access),
                        name=ident)
        if constraint_func is not None:
            self.conditions.append(constraint_func(table, self.data_access))
        self.variables[ident] = Variable({'identifier': ident,
                                          'entity': entity,
                                          'table': table})

    def on_enter_join(self, join):
        """Translates the join into an actual
        where clause depending on how the relation
        is defined in the allowed_joins data structure.

        Args:
            join (ast.Join): Join AST node
        Raises:
            Exception: Raised if the relation cannot be found
            TypeError: If the relation exists but expects different params
        """
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
                    elif var.entity != arg_type:
                        raise TypeError(
                            'Relation: {}, expected: {}, actual: {}'.format(
                                relation, arg_type, var.entity))

                self.join_clauses.append(
                    generator(self.data_access,
                              obj,
                              *map(lambda ident:
                                   self.variables[ident], join.arglist)))
                return
        raise Exception('Undefined join relationship: {}'.format(join))

    def on_leave_unsafe_join(self, join, artefacts):
        """Translates two unsafe attribute accesses to a where
        clause and adds it to the global set of query clauses.

        Args:
            join (ast.UnsafeJoin): UnsafeJoin AST node.
            artefacts (list): Right and left unsafe attribute access
        """
        self.conditions.append(artefacts[0] == artefacts[1])

    def on_leave_unsafe_jointarget(self, target, artefacts):
        """Translates a JoinTarget into the corresponding
        table attribute access.

        Args:
            target (ast.UnsafeJoinTarget): UnsafeJoinTarget AST node
            artefacts (list): Unused
        Returns:
            object: Attribute access clause
        """
        variable = self.variables[target.name]
        attribute_ref = target.attribute
        return getattr(variable['table'], attribute_ref.name)

    def on_leave_comparison(self, comparison, artefacts):
        """Translates a comparison into a where clause
        which is returned as an artifact.

        Args:
            comparison (object): Operator
            artefacts (list): Left and right operands
        Returns:
            object: where clause
        Raises:
            Exception: If the comparison is not performed with an attribute
        """
        if isinstance(comparison.right, ast.Attribute):
            attribute = artefacts[1]
            literal = artefacts[0]
        elif isinstance(comparison.left, ast.Attribute):
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
        """Translates an attribute access into the corresponding
        table attribute access.

        Args:
            attribute (object): Operator
            artefacts (list): Left and right operands
        Returns:
            object: Attribute access
        """
        variable = self.variables[attribute.entity_def.identifier]
        return getattr(variable['table'], attribute.name)

    def on_leave_scalar(self, scalar, artefacts):
        """Translates a scalar into its underlying value

        Args:
            scalar (ast.Scalar): Scalar AST node
            artefacts (list): Unused
        Returns:
            object: Scalar value
        """
        return scalar.value

    def on_leave_entityfilter(self, entity_filter, artefacts):
        """Adds a translated entity filter expression
        to the set of global clauses.

        Args:
            entity_filter (ast.EntityFilter): EntityFilter AST node
            artefacts (list): Clauses to add to global query state
        """
        for artefact in artefacts:
            self.conditions.append(artefact)

    def on_leave_not(self, operator, artefacts):
        """Translation of entity filter 'not' operator
        Args:
            operator (ast.Node): Operator AST node
            artefacts (object): Translated expression operand
        Returns:
            object: not(expr) clause
        """
        return not_(*artefacts)

    def on_leave_and(self, operator, artefacts):
        """Translation of entity filter 'and' operator
        Args:
            operator (ast.Node): Operator AST node
            artefacts (object): Translated expression operands
        Returns:
            object: and(x1,x2,x3,x4...) clause
        """
        return and_(*artefacts)

    def on_leave_or(self, operator, artefacts):
        """Translation of entity filter 'or' operator
        Args:
            operator (ast.Node): Operator AST node
            artefacts (object): Translated expression operands
        Returns:
            object: or(x1,x2,x3,x4...) clause
        """
        return or_(*artefacts)

    def on_leave_in(self, operator, artefacts):
        """Translation of entity filter 'in' operator
        Args:
            operator (ast.Node): Operator AST node
            artefacts (object): Translated expression operands
        Returns:
            object: attribute in [x1,x2,x3,x4] clause
        """
        attribute = artefacts[0]
        literal_list = artefacts[1]
        return attribute.in_(literal_list)

    def on_leave_like(self, operator, artefacts):
        """Translation of entity filter 'like' operator
        Args:
            operator (ast.Node): Operator AST node
            artefacts (object): Unused
        Returns:
            object: attribute like "str" clause
        """
        attribute = artefacts[0]
        return attribute.like(operator.literal.value)

    def enter(self, node):
        """Called upon entering an AST node.
        Dispatches to handler if exists.

        Args:
            node (ast.Node): AST node to dispatch
        """
        handlers = {
            ast.SafeJoin: self.on_enter_join,
            ast.Projection: self.on_enter_projection,
            ast.EntityDefinition: self.on_enter_entity_definition,
            }
        self._exec_matching_handler(handlers, node)

    def leave(self, node, artefacts):
        """Called upon leaving an AST node.
        Dispatches to handler if exists.

        Args:
            node (ast.Node): AST node to dispatch
            artefacts (list): Results from child node compilations
        Returns:
            object: Whatever artifacts returned by the handler
        """
        handlers = {
            ast.UnsafeJoin: self.on_leave_unsafe_join,
            ast.UnsafeJoinTarget: self.on_leave_unsafe_jointarget,
            ast.Query: self.on_leave_query,
            ast.Comparison: self.on_leave_comparison,
            ast.Attribute: self.on_leave_attribute,
            ast.Scalar: self.on_leave_scalar,
            ast.EntityFilter: self.on_leave_entityfilter,
            ast.Not: self.on_leave_not,
            ast.And: self.on_leave_and,
            ast.Or: self.on_leave_or,
            ast.LikeOperator: self.on_leave_like,
            ast.InOperator: self.on_leave_in,
            }
        return self._exec_matching_handler(handlers, node, artefacts)

    def _exec_matching_handler(self, handlers, node, artefacts=None):
        """Executes the first matching handler for the node.
        Args:
            handlers (dict): Handler dictionary
            node (Node): AST node
            artefacts (list): Optional list of compiled artifacts
        Returns:
            object: Whatever artifacts returned by the handler
        """
        for cls, handler in handlers.iteritems():
            if isinstance(node, cls):
                if artefacts is not None:
                    return handler(node, artefacts)
                return handler(node)
        return artefacts


class QueryCompiler(object):
    """Main compiler front-end."""

    def __init__(self, data_access, session, iam_query):
        """Constructor
        Args:
            data_access (object): Data access object
            session (object): Database session
            iam_query (str): Query
        """
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
        parsed_ast = BNF().parseString(self.iam_query, parseAll=True)
        query_set = parsed_ast[0]

        context = CompilationContext(self.data_access,
                                     Metadata.entity_attributes,
                                     Metadata.allowed_joins,
                                     self.session)

        artefact = query_set.compile(context)
        return artefact
