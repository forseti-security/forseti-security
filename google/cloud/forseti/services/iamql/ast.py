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
