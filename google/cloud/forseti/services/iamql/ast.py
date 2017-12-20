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

"""IAMQL AST nodes"""

from pyparsing import Group
from google.cloud.forseti.services.iamql.relations import Metadata

# pylint: disable=invalid-name,protected-access,no-self-use


class Node(list):
    """AST node base class"""

    def __init__(self, orig, loc, args):
        """Constructor.
        Args:
            orig (object): Original token
            loc (object): Location of token
            args (object): Nested arguments
        """
        super(Node, self).__init__(args)
        self.orig = orig
        self.loc = loc

        self._connected = False
        self._parent = None

    def __eq__(self, other):
        """== implementation
        Args:
            other (object): Object to compare to
        Returns:
            bool: if self and other are equal
        """
        return (
            self.__class__ == other.__class__ and
            super(Node, self).__eq__(other))

    @classmethod
    def build(cls, e):
        """Helper to create AST node objects from parser.
        Args:
            e (object): Grammar node.
        Returns:
            object: Node object.
        """
        def action(s, l, t):
            """Action function for parser
            Args:
                s (object): Token
                l (object): Location
                t (object): Arguments
            Returns:
                list: With single element instantiated AST node
            """
            try:
                lst = t[0].asList()
            except IndexError:
                lst = t
            return [cls(s, l, lst)]
        return Group(e).setParseAction(action)

    def __repr__(self):
        """String representation
        Returns:
            str: String representation.
        """
        return '{}@{}({})'.format(
            self.__class__.__name__,
            self.loc,
            super(Node, self).__repr__())

    def accept(self, visitor):
        """Accept implementation for visitor pattern
        Args:
            visitor (object): Visitor
        Returns:
            object: Visitor result propagated
        """
        if not self._connected:
            self.connect()
        new_nodes = []
        for node in self:
            if isinstance(node, Node):
                new_nodes.append(node.accept(visitor))
        return visitor.visit(self, new_nodes)

    def connect(self, parent=None):
        """Create child-parent connections in the AST
        Args:
            parent (object): AST parent node
        """
        if not self._connected:
            self._connected = True
            self._parent = parent

            for item in self:
                if isinstance(item, Node):
                    item.connect(self)

    def _find_ancestor(self, cls):
        """Find AST ancestor by type.
        Args:
            cls (classobj): Class to look for in ancestors
        Returns:
            object: First matching ancestor
        """
        if not self._parent:
            return None
        elif isinstance(self, cls):
            return self
        return self._parent._find_ancestor(cls)

    def typecheck(self):
        """Perform type checking on the node, no-op base implementation.
        Returns:
            list: Stub implementation.
        """
        return []

    def compile(self, context):
        """Compile this node using a compilation context
        Args:
            context (object): Compilation context
        Returns:
            object: Compilation artefact
        """
        if not self._connected:
            self.connect()

        context.enter(self)
        artefacts = []
        for item in self:
            if isinstance(item, Node):
                artefacts.append(item.compile(context))
        return context.leave(self, artefacts)


class QuerySet(Node):
    """QuerySet node"""

    def compile(self, context):
        """This is the AST root returning the compilation artefact
        Args:
            context (object): Compilation context
        Returns:
            object: Compilation artefact"""
        Node.compile(self, context)
        return context.artefact


class Selection(Node):
    """Selection node"""
    pass


class Projection(Node):
    """Projection node"""

    @property
    def entities(self):
        """Access to entities mentioned in the projection

        Returns:
            list: List of all entities mentioned
        """
        return [item for sublist in self for item in sublist]


class JoinList(Node):
    """JoinList node"""
    pass


class SafeJoin(Node):
    """SafeJoin node"""

    @property
    def object(self):
        """Access to the join object variable name
        Returns:
            str: identifier
        """
        return self[0]

    @property
    def relation(self):
        """Access to the relation name
        Returns:
            str: Relation name
        """
        return self[1]

    @property
    def arglist(self):
        """Access to relation parameter list
        Returns:
            list: Relation parameter list
        """
        return self[2]


class UnsafeJoinTarget(Node):
    """UnsafeJoinTarget node"""

    @property
    def name(self):
        """Access to join object variable name
        Returns:
            str: identifier
        """
        return self[0]

    @property
    def attribute(self):
        """Access to attribute name joined on
        Returns:
            str: attribute name
        """
        return self[1]

    def type_of(self):
        """Get the type of the attribute
        Returns:
            object: Type of the attribute
        """
        return self.attribute.type_of()


class UnsafeJoin(Node):
    """UnsafeJoin node"""

    @property
    def src(self):
        """Get the source UnsafeJoinTarget
        Returns:
            UnsafeJoinTarget: Join target
        """
        return self[0]

    @property
    def dst(self):
        """Get the destination UnsafeJoinTarget
        Returns:
            UnsafeJoinTarget: Join target
        """
        return self[1]

    def typecheck(self):
        """Type check implementation
        Raises:
            TypeError: If join targets are of distinct type
        """
        if self.src.type_of() != self.dst.type_of():
            raise TypeError('type({}) != type({})'.format(self.src,
                                                          self.dst))


class Query(Node):
    """Query node"""

    @property
    def name(self):
        """Get the query name
        Returns:
            str: Query name
        """
        return self[0]


class QueryName(Node):
    """Query name"""

    def __str__(self):
        """String conversion
        Returns:
            str: Query name
        """
        return self[0]

    def __hash__(self):
        """Hash implementation
        Returns:
            int: Hash of the object
        """
        return self[0].__hash__()


class EntityDefinition(Node):
    """EntityDefinition node"""

    @property
    def identifier(self):
        """Variable identifier
        Returns:
            str: identifier string
        """
        return self[0]

    @property
    def entity(self):
        """Variable entity type
        Returns:
            str: entity type string
        """
        return self[1]


class EntityFilter(Node):
    """EntityFilter node"""
    pass


class Not(Node):
    """Not node"""
    pass


class Paren(Node):
    """Parenthesis node"""
    pass


class Attribute(Node):
    """Attribute node"""

    def __init__(self, *args, **kwargs):
        """Constructor
        Args:
            args (list): Forwarded to base class
            kwargs (dict): Forwarded to base class
        """
        super(Attribute, self).__init__(*args, **kwargs)
        self.attribute_type = None

    @property
    def name(self):
        """Access to attribute name
        Returns:
            str: Attribute name string
        """
        return self[0]

    @property
    def entity_def(self):
        """Access to entity definition node
        Returns:
            object: Entity definition
        Raises:
            Exception: If ancestor cannot be found
        """
        entity_def = self._find_ancestor(EntityDefinition)
        if entity_def is None:
            raise Exception('Unable to find ancestor node')
        return entity_def

    def _find_entity_def(self):
        """Find the corresponding entity definition
        Returns:
            object: EntityDefinition if found
        """
        return self._find_ancestor(EntityDefinition)

    def typecheck(self):
        """Perform a type check
        Returns:
            object: Type of the attribute
        """
        entity = self.entity_def.entity
        self.attribute_type = (
            Metadata.entity_attributes[entity][self.name]['type'])
        return self.attribute_type

    def type_of(self):
        """Access to the attribute type
        Returns:
            object: Type of the attribute
        """
        return (self.attribute_type
                if self.attribute_type
                else self.typecheck())


class AttributeRef(Node):
    """AttributeRef node"""

    @property
    def name(self):
        """Access to the attribute reference name
        Returns:
            str: Identifier
        """
        return self[0]

    def type_of(self):
        """Type of the attribute ref
        """
        return None


class Operator(Node):
    """Operator node"""

    @property
    def op(self):
        """Access to the operation name
        Returns:
            str: name of the operation
        """
        return self[1]

    @property
    def right(self):
        """Access to the right operator
        Returns:
            object: Right operator
        """
        return self[2]

    @property
    def left(self):
        """Access to the left operator
        Returns:
            object: Left operator
        """
        return self[0]

    def typecheck(self):
        """Perform a type check
        Raises:
            TypeError: If the type check fails
        """
        self.left.typecheck()
        self.right.typecheck()

        if self.right.type_of() != self.left.type_of():
            raise TypeError('type({}) != type({})'.format(self.left,
                                                          self.right))


class And(Operator):
    """And node"""
    pass


class Or(Operator):
    """Or node"""
    pass


class Scalar(Node):
    """Scalar node"""
    pass


class String(Scalar):
    """String node"""

    @property
    def value(self):
        """Access string value
        Returns:
            str: value string
        """
        return self[0][1:-1]

    def type_of(self):
        """Type of string
        Returns:
            type: Unicode
        """
        return unicode


class Number(Scalar):
    """Number node"""

    @property
    def value(self):
        """Access value
        Returns:
            str: value string representation
        """
        return self[0]

    def type_of(self):
        """Type of number
        Returns:
            type: int
        """
        return int


class Comparison(Operator):
    """Comparison node"""
    pass


class InOperator(Node):
    """InOperator node"""
    pass


class LikeOperator(Operator):
    """LikeOperator node"""

    @property
    def literal(self):
        """Access the like comparison literal
        Returns:
            object: Literal ast object
        """
        return self[1]


class LiteralList(Node):
    """LiteralList node"""

    @property
    def value(self):
        """Access the list
        Returns:
            list: Containing literals
        """
        return [x.value for x in self]

    def typecheck(self):
        """Perform type check
        Raises:
            TypeError: If the type check fails
        """
        t = self.type_of()
        for item in self:
            item_type = item.type_of()
            if t != item_type:
                raise TypeError(
                    'list type: {}, item type: {}'.format(
                        t, item_type))

    def type_of(self):
        """Type of literal list
        Returns:
            list: List with type element of type list[0]
        """
        return [self[0].type_of()]
