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

"""Database abstraction objects for Forseti Server."""

# pylint: disable=too-many-lines,singleton-comparison,no-value-for-parameter

import datetime
import os
import binascii
import collections
import struct
import hmac
from threading import Lock

from sqlalchemy import Column
from sqlalchemy import event
from sqlalchemy import Integer
from sqlalchemy import Boolean
from sqlalchemy import String
from sqlalchemy import Sequence
from sqlalchemy import ForeignKey
from sqlalchemy import Text
from sqlalchemy import create_engine as sqlalchemy_create_engine
from sqlalchemy import Table
from sqlalchemy import DateTime
from sqlalchemy import or_
from sqlalchemy import and_
from sqlalchemy import func
from sqlalchemy.orm import relationship
from sqlalchemy.orm import aliased
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm import reconstructor
from sqlalchemy.sql import select
from sqlalchemy.ext.declarative import declarative_base

from google.cloud.forseti.services.utils import mutual_exclusive
from google.cloud.forseti.services.utils import to_full_resource_name
from google.cloud.forseti.services import db
from google.cloud.forseti.services.utils import get_sql_dialect
from google.cloud.forseti.services.iamql import compiler as iamql


# TODO: The next editor must remove this disable and correct issues.
# pylint: disable=missing-type-doc,missing-return-type-doc,missing-return-doc
# pylint: disable=missing-param-doc,missing-raises-doc
# pylint: disable=missing-yield-type-doc

POOL_RECYCLE_SECONDS = 300
PER_YIELD = 1024


def generate_model_handle():
    """Generate random model handle."""

    return binascii.hexlify(os.urandom(16))


def generate_model_seed():
    """Generate random model seed."""

    return binascii.hexlify(os.urandom(16))


MODEL_BASE = declarative_base()


class Model(MODEL_BASE):
    """Explain model object in database."""

    __tablename__ = 'model'
    name = Column(String(32), primary_key=True)
    handle = Column(String(32))
    state = Column(String(32))
    watchdog_timer = Column(DateTime)
    created_at = Column(DateTime)
    etag_seed = Column(String(32), nullable=False)
    message = Column(Text())
    warnings = Column(Text(16777215))

    def __init__(self, *args, **kwargs):
        super(Model, self).__init__(*args, **kwargs)
        # Non-SQL attributes
        self.warning_store = list()

    @reconstructor
    def init_on_load(self):
        """Initialization of model when reconstructed from query."""
        self.warning_store = list()

    def kick_watchdog(self):
        """Used during import to notify the import is still progressing."""

        self.watchdog_timer = datetime.datetime.utcnow()

    def add_warning(self, warning):
        """Add a warning to the model.

        Args:
            warning (str): Warning message
        """
        if warning:
            self.warning_store.append(warning)

    def get_warnings(self):
        """Returns any stored warnings."""
        if self.warning_store:
            return "\n".join(self.warning_store)
        return ""

    def set_inprogress(self):
        """Set state to 'in progress'."""

        self.state = "INPROGRESS"

    def set_done(self, message=''):
        """Indicate a finished import.
            Args:
                message (str): Success message or ''
        """

        if self.get_warnings():
            self.warnings = self.get_warnings()
            self.state = "PARTIAL_SUCCESS"
        else:
            self.state = "SUCCESS"
        self.message = message

    def set_error(self, message):
        """Indicate a broken import."""

        self.state = "BROKEN"
        self.warnings = self.get_warnings()
        self.message = message

    def __repr__(self):
        """String representation."""

        return "<Model(name='{}', handle='{}' state='{}')>".format(
            self.name, self.handle, self.state)


# pylint: disable=too-many-locals,no-member
def define_model(model_name, dbengine, model_seed):
    """Defines table classes which point to the corresponding model.

        This means, for each model being accessed this function needs to
        be called in order to generate a full set of table definitions.

        Models are name spaced via a random model seed such that multiple
        models can exist within the same database. In order to implement
        the name spacing in an abstract way.
    """

    base = declarative_base()

    denormed_group_in_group = '{}_group_in_group'.format(model_name)
    bindings_tablename = '{}_bindings'.format(model_name)
    roles_tablename = '{}_roles'.format(model_name)
    permissions_tablename = '{}_permissions'.format(model_name)
    members_tablename = '{}_members'.format(model_name)
    resources_tablename = '{}_resources'.format(model_name)

    role_permissions = Table('{}_role_permissions'.format(model_name),
                             base.metadata,
                             Column(
                                 'roles_name', ForeignKey(
                                     '{}.name'.format(roles_tablename)),
                                 primary_key=True),
                             Column(
                                 'permissions_name', ForeignKey(
                                     '{}.name'.format(permissions_tablename)),
                                 primary_key=True), )

    binding_members = Table('{}_binding_members'.format(model_name),
                            base.metadata,
                            Column(
                                'bindings_id', ForeignKey(
                                    '{}.id'.format(bindings_tablename)),
                                primary_key=True),
                            Column(
                                'members_name', ForeignKey(
                                    '{}.name'.format(members_tablename)),
                                primary_key=True), )

    group_members = Table('{}_group_members'.format(model_name),
                          base.metadata,
                          Column('group_name', ForeignKey(
                              '{}.name'.format(members_tablename)),
                                 primary_key=True),
                          Column('members_name', ForeignKey(
                              '{}.name'.format(members_tablename)),
                                 primary_key=True), )

    class Resource(base):
        """Row entry for a GCP resource."""
        __tablename__ = resources_tablename

        full_name = Column(String(1024), nullable=False)
        type_name = Column(String(256), primary_key=True)
        name = Column(String(128), nullable=False)
        type = Column(String(64), nullable=False)
        policy_update_counter = Column(Integer, default=0)
        display_name = Column(String(256), default='')
        email = Column(String(256), default='')
        data = Column(Text)

        parent_type_name = Column(
            String(128),
            ForeignKey('{}.type_name'.format(resources_tablename)))
        parent = relationship("Resource", remote_side=[type_name])
        bindings = relationship('Binding', back_populates="resource")

        def increment_update_counter(self):
            """Increments counter for this object's db updates."""
            self.policy_update_counter += 1

        def get_etag(self):
            """Return the etag for this resource."""
            serialized_ctr = struct.pack('>I', self.policy_update_counter)
            msg = binascii.hexlify(serialized_ctr)
            msg += self.full_name
            return hmac.new(model_seed.encode('utf-8'), msg).hexdigest()

        def __repr__(self):
            """String representation."""
            return "<Resource(full_name='{}', name='{}' type='{}')>".format(
                self.full_name, self.name, self.type)

        def _column_decls(self):
            """Get column name/type
            Returns:
                dict: name to attribute/type mapping
            """
            return {
                'name': (self.name, unicode),
                'type': (self.type, unicode),
                'display_name': (self.display_name, unicode),
                'full_name': (self.full_name, unicode),
                'policy_update_counter': (self.policy_update_counter, int),
                'email': (self.email, unicode),
                }

        def get_columns(self):
            """Get name/attribute mapping
            Returns:
                dict: name/attribute mapping
            """
            return {k: v[0] for k, v in self._column_decls().iteritems()}

        def get_column_type(self, column):
            """Get column type
            Returns:
                object: Type of the column
            """
            return self._column_decls()[column][1]

    Resource.children = relationship(
        "Resource", order_by=Resource.full_name, back_populates="parent")

    class Member(base):
        """Row entry for a policy member."""

        TYPE_GROUP = 'group'

        __tablename__ = members_tablename
        name = Column(String(256), primary_key=True)
        type = Column(String(64))
        member_name = Column(String(128))

        CORE_TYPES = [
            'group',
            'serviceAccount',
            'user',
            'allUsers',
            'allAuthenticatedUsers']

        parents = relationship(
            'Member',
            secondary=group_members,
            primaryjoin=name == group_members.c.members_name,
            secondaryjoin=name == group_members.c.group_name)

        children = relationship(
            'Member',
            secondary=group_members,
            primaryjoin=name == group_members.c.group_name,
            secondaryjoin=name == group_members.c.members_name)

        bindings = relationship('Binding',
                                secondary=binding_members,
                                back_populates='members')

        def __repr__(self):
            """String representation."""
            return "<Member(name='{}', type='{}')>".format(
                self.name, self.type)

        def _column_decls(self):
            """Get column name/type
            Returns:
                dict: name to attribute/type mapping
            """
            return {
                'name': (self.name, unicode),
                'type': (self.type, unicode),
                'member_name': (self.member_name, unicode),
                }

        def get_columns(self):
            """Get column attribute/type mapping
            Returns:
                dict: attribute/type mapping
            """
            return {k: v[0] for k, v in self._column_decls().iteritems()}

        def get_column_type(self, column):
            """Get column type
            Returns:
                object: Type of the column
            """
            return self._column_decls()[column][1]

    class GroupInGroup(base):
        """Row for a group-in-group membership."""

        __tablename__ = denormed_group_in_group
        parent = Column(String(256), primary_key=True)
        member = Column(String(256), primary_key=True)

        def __repr__(self):
            """String representation."""
            return "<GroupInGroup(parent='{}', member='{}')>".format(
                self.parent,
                self.member)

    class Binding(base):
        """Row for a binding between resource, roles and members."""

        __tablename__ = bindings_tablename
        id = Column(Integer, Sequence('{}_id_seq'.format(bindings_tablename)),
                    primary_key=True)

        resource_type_name = Column(String(128), ForeignKey(
            '{}.type_name'.format(resources_tablename)))
        role_name = Column(String(128), ForeignKey(
            '{}.name'.format(roles_tablename)))

        resource = relationship('Resource', remote_side=[resource_type_name])
        role = relationship('Role', remote_side=[role_name])

        members = relationship('Member',
                               secondary=binding_members,
                               back_populates='bindings')

        def __repr__(self):
            fmt_s = "<Binding(id='{}', role='{}', resource='{}' members='{}')>"
            return fmt_s.format(
                self.id,
                self.role_name,
                self.resource_type_name,
                self.members)

        def _column_decls(self):
            """Get column name/type
            Returns:
                dict: name to attribute/type mapping
            """
            return {
                'resource': (self.resource_type_name, unicode),
                'role': (self.role_name, unicode),
                }

        def get_columns(self):
            """Get column attribute/type mapping
            Returns:
                dict: attribute/type mapping
            """
            return {k: v[0] for k, v in self._column_decls().iteritems()}

        def get_column_type(self, column):
            """Get column type
            Returns:
                object: Type of the column
            """
            return self._column_decls()[column][1]

    class Role(base):
        """Row entry for an IAM role."""

        __tablename__ = roles_tablename
        name = Column(String(128), primary_key=True)
        title = Column(String(128), default='')
        stage = Column(String(128), default='')
        description = Column(String(256), default='')
        custom = Column(Boolean, default=False)
        permissions = relationship('Permission',
                                   secondary=role_permissions,
                                   back_populates='roles')

        def __repr__(self):
            return "<Role(name='%s')>" % (self.name)

        def _column_decls(self):
            """Get column name/type
            Returns:
                dict: name to attribute/type mapping
            """
            return {
                'name': (self.name, unicode),
                'title': (self.title, unicode),
                'description': (self.description, unicode),
                'custom': (self.custom, int),
                }

        def get_columns(self):
            """Get column attribute/type mapping
            Returns:
                dict: attribute/type mapping
            """
            return {k: v[0] for k, v in self._column_decls().iteritems()}

        def get_column_type(self, column):
            """Get column type
            Returns:
                object: Type of the column
            """
            return self._column_decls()[column][1]

    class Permission(base):
        """Row entry for an IAM permission."""

        __tablename__ = permissions_tablename
        name = Column(String(128), primary_key=True)
        roles = relationship('Role',
                             secondary=role_permissions,
                             back_populates='permissions')

        def __repr__(self):
            return "<Permission(name='%s')>" % (self.name)

        def _column_decls(self):
            """Get column name/type
            Returns:
                dict: name to attribute/type mapping
            """
            return {
                'name': (self.name, unicode),
                }

        def get_columns(self):
            """Get column attribute/type mapping
            Returns:
                dict: attribute/type mapping
            """
            return {k: v[0] for k, v in self._column_decls().iteritems()}

        def get_column_type(self, column):
            """Get column type
            Returns:
                object: Type of the column
            """
            return self._column_decls()[column][1]

    # pylint: disable=too-many-public-methods
    class ModelAccess(object):
        """Data model facade, implement main API against database."""

        TBL_GROUP_IN_GROUP = GroupInGroup
        TBL_BINDING = Binding
        TBL_MEMBER = Member
        TBL_PERMISSION = Permission
        TBL_ROLE = Role
        TBL_RESOURCE = Resource
        TBL_MEMBERSHIP = group_members
        TBL_ROLE_PERMISSION = base.metadata.tables[
            '{}_role_permissions'.format(model_name)]
        TBL_GROUP_MEMBERS = base.metadata.tables[
            '{}_group_members'.format(model_name)]
        TBL_BINDING_MEMBERS = base.metadata.tables[
            '{}_binding_members'.format(model_name)]

        @classmethod
        def delete_all(cls, engine):
            """Delete all data from the model."""
            role_permissions.drop(engine)
            binding_members.drop(engine)
            group_members.drop(engine)

            Binding.__table__.drop(engine)
            Permission.__table__.drop(engine)
            GroupInGroup.__table__.drop(engine)

            Role.__table__.drop(engine)
            Member.__table__.drop(engine)
            Resource.__table__.drop(engine)

        @classmethod
        def iamql_query(cls, session, iam_query):
            """Implement IAMQL query functionality.

            Args:
                session (object): Database session to use.
                iam_query (str): Query to execute.

            Yields:
                list(object): Returned rows
            """

            db_query = iamql.QueryCompiler(cls, session, iam_query).compile()
            for row in db_query.yield_per(PER_YIELD):
                try:
                    len(row)
                except TypeError:
                    row = (row,)
                column_desc = db_query.column_descriptions
                converted_row = {}
                for index, item in enumerate(row):
                    converted_row[index] = column_desc[index]['name']
                    converted_row[converted_row[index]] = (
                        {name: value
                         for name, value
                         in item.get_columns().iteritems()})
                yield converted_row

        @classmethod
        def denorm_group_in_group(cls, session):
            """Denormalize group-in-group relation.

            Args:
                session (object): Database session to use.
            Returns:
                int: Number of iterations.
            """

            tbl1 = aliased(GroupInGroup.__table__, name='alias1')
            tbl2 = aliased(GroupInGroup.__table__, name='alias2')
            tbl3 = aliased(GroupInGroup.__table__, name='alias3')

            if get_sql_dialect(session) != 'sqlite':
                # Lock tables for denormalization
                # including aliases 1-3
                locked_tables = [
                    '`{}`'.format(GroupInGroup.__tablename__),
                    '`{}` as {}'.format(
                        GroupInGroup.__tablename__,
                        tbl1.name),
                    '`{}` as {}'.format(
                        GroupInGroup.__tablename__,
                        tbl2.name),
                    '`{}` as {}'.format(
                        GroupInGroup.__tablename__,
                        tbl3.name),
                    '`{}`'.format(group_members.name),
                    '`{}`'.format(Member.__tablename__)]
                lock_stmts = ['{} WRITE'.format(tbl) for tbl in locked_tables]
                query = 'LOCK TABLES {}'.format(', '.join(lock_stmts))
                session.execute(query)

            try:
                # Remove all existing rows in the denormalization
                session.execute(GroupInGroup.__table__.delete())

                # Remove all group members point to themselves
                # We will recreate them again immediately after
                # to account for changes in the Member table.
                session.execute(
                    group_members
                    .delete()
                    .where(
                        (group_members.c.group_name ==
                         group_members.c.members_name)))

                # Select (member.name, member.name) from member
                stmt = (
                    select([Member.name.label('parent'),
                            Member.name.label('member')])
                    .select_from(Member.__table__)
                    .distinct()
                    )

                # Insert (member, member) into group_members
                qry = (
                    group_members.insert()
                    .from_select(
                        ['group_name', 'members_name'],
                        stmt)
                    )
                session.execute(qry)

                qry = (
                    GroupInGroup.__table__.insert()
                    .from_select(
                        ['parent', 'member'],
                        group_members.select())
                    )
                session.execute(qry)

                iterations = 0
                rows_affected = True
                while rows_affected:

                    # Join membership on its own to find transitive
                    expansion = tbl1.join(tbl2, tbl1.c.member == tbl2.c.parent)

                    # Left outjoin to find the entries that
                    # are already in the table to prevent
                    # inserting already existing entries
                    expansion = expansion.outerjoin(
                        tbl3,
                        and_(tbl1.c.parent == tbl3.c.parent,
                             tbl2.c.member == tbl3.c.member))

                    # Select only such elements that are not
                    # already in the table, indicated as NULL
                    # values through the outer-left-join
                    stmt = (
                        select([tbl1.c.parent, tbl2.c.member])
                        .select_from(expansion)
                        .where(tbl3.c.parent == None)
                        .distinct())

                    # Execute the query and insert into the table
                    qry = (
                        GroupInGroup.__table__.insert()
                        .from_select(
                            ['parent', 'member'],
                            stmt))

                    rows_affected = bool(session.execute(qry).rowcount)
                    iterations += 1

            except Exception:
                session.rollback()
                raise
            finally:
                if get_sql_dialect(session) != 'sqlite':
                    session.execute('UNLOCK TABLES')
                session.commit()
            return iterations

        @classmethod
        def explain_granted(cls, session, member_name, resource_type_name,
                            role_name, permission_name):
            """Provide info about how the member has access to the resource."""

            resource_ancestor = aliased(Resource)
            resource_child = aliased(Resource)
            member_ancestor = aliased(Member)
            member_child = aliased(Member)
            group_in_group = aliased(GroupInGroup)
            binding = aliased(Binding)

            qry = session.query(binding, member_child)
            qry = (
                qry
                .filter(
                    resource_child.type_name == resource_type_name,
                    resource_child.full_name.startswith(
                        resource_ancestor.full_name)
                    )
                .filter(
                    member_child.name == member_name,
                    group_in_group.parent == member_ancestor.name,
                    group_in_group.member == group_members.c.group_name,
                    group_members.c.members_name == member_child.name
                    )
                .filter(
                    binding_members.c.bindings_id == binding.id,
                    binding_members.c.members_name == member_ancestor.name,
                    binding.resource_type_name == resource_ancestor.type_name
                    )
                )

            if role_name:
                qry = (
                    qry
                    .filter(
                        binding.role_name == role_name
                        )
                    )
            elif permission_name:
                qry = (
                    qry.filter(
                        role_permissions.c.roles_name == binding.role_name,
                        role_permissions.c.permissions_name == permission_name
                        )
                    )

            result = qry.all()

            members, member_graph = cls.reverse_expand_members(
                session, [member_name], request_graph=True)
            member_names = [m.name for m in members]
            resource_type_names = [r.type_name for r in
                                   cls.find_resource_path(session,
                                                          resource_type_name)]

            if not result:
                raise Exception(
                    'Grant not found: ({},{},{})'.format(
                        member_name,
                        resource_type_name,
                        role if role is not None else permission))
            else:
                bindings = [(b.resource_type_name, b.role_name, m.name)
                            for b, m in result]
                return bindings, member_graph, resource_type_names

        @classmethod
        def scanner_iter(cls, session, resource_type):
            """Iterate over all resources with the specified type."""

            qry = (
                session.query(Resource)
                .filter(Resource.type == resource_type))

            return iter(qry.yield_per(PER_YIELD))

        @classmethod
        def explain_denied(cls, session, member_name, resource_type_names,
                           permission_names, role_names):
            """Provide information how to grant access to a member."""

            if not role_names:
                role_names = [r.name for r in
                              cls.get_roles_by_permission_names(
                                  session,
                                  permission_names)]
                if not role_names:
                    raise Exception(
                        'No roles covering requested permission set')

            resource_hierarchy = (
                cls.resource_ancestors(session,
                                       resource_type_names))

            def find_binding_candidates(resource_hierarchy):
                """Find the root node in the ancestors.

                    From there, walk down the resource tree and add
                    every node until a node has more than one child.
                    This is the set of nodes which grants access to
                    at least all of the resources requested.
                    There is always a chain with a single node root.
                """

                root = None
                for parent in resource_hierarchy.iterkeys():
                    is_root = True
                    for children in resource_hierarchy.itervalues():
                        if parent in children:
                            is_root = False
                            break
                    if is_root:
                        root = parent
                chain = [root]
                cur = root
                while len(resource_hierarchy[cur]) == 1:
                    cur = iter(resource_hierarchy[cur]).next()
                    chain.append(cur)
                return chain

            bind_res_candidates = find_binding_candidates(
                resource_hierarchy)

            bindings = (
                session.query(Binding, Member)
                .join(binding_members).join(Member).join(Role)
                .filter(Binding.resource_type_name.in_(bind_res_candidates))
                .filter(Role.name.in_(role_names))
                .filter(or_(Member.type == 'group',
                            Member.name == member_name))
                .filter(and_(binding_members.c.bindings_id == Binding.id,
                             binding_members.c.members_name == Member.name))
                .filter(Role.name == Binding.role_name)
                .all())

            strategies = []
            for resource in bind_res_candidates:
                for role_name in role_names:
                    overgranting = (len(bind_res_candidates) -
                                    bind_res_candidates.index(resource) -
                                    1)
                    strategies.append(
                        (overgranting, [
                            (role, member_name, resource)
                            for role in [role_name]]))
            if bindings:
                for binding, member in bindings:
                    overgranting = (len(bind_res_candidates) - 1 -
                                    bind_res_candidates.index(
                                        binding.resource_type_name))
                    strategies.append(
                        (overgranting, [
                            (binding.role_name,
                             member.name,
                             binding.resource_type_name)]))

            return strategies

        @classmethod
        def query_access_by_member(cls, session, member_name, permission_names,
                                   expand_resources=False,
                                   reverse_expand_members=True):
            """Return the set of resources the member has access to."""

            expanded = aliased(Resource)
            resource = aliased(Resource)
            role = aliased(Role)
            group_in_group = aliased(GroupInGroup)
            expanded_member = aliased(Member)
            direct_member = aliased(Member)
            group = aliased(Member)
            b_members = binding_members

            if expand_resources:
                qry = (
                    session.query(role, expanded)
                    .filter(expanded.full_name.startswith(resource.full_name))
                    )
            else:
                qry = (
                    session.query(role, resource)
                    )

            qry = (
                qry

                # Reduce to mentioned permissions
                .filter(Permission.name.in_(permission_names))

                # Associate roles to selected permissions
                .filter(role.name == role_permissions.c.roles_name)
                .filter(Permission.name == role_permissions.c.permissions_name)

                # Associate role <-> binding <-> resource
                .filter(resource.type_name == Binding.resource_type_name)
                .filter(role.name == Binding.role_name)

                )

            if reverse_expand_members:
                qry = (qry.filter(or_(

                    # Directly mentioned in policy
                    and_(
                        b_members.c.bindings_id == Binding.id,
                        b_members.c.members_name == member_name,
                        ),

                    # Transitive group membership
                    and_(
                        b_members.c.bindings_id == Binding.id,
                        b_members.c.members_name == direct_member.name,
                        direct_member.type == Member.TYPE_GROUP,
                        group_in_group.parent == direct_member.name,
                        group_in_group.member == group.name,
                        group.name == group_members.c.group_name,
                        expanded_member.name == group_members.c.members_name,
                        expanded_member.name == member_name,
                        ),

                    # Expanded member is direct member of group in policy
                    and_(
                        b_members.c.bindings_id == Binding.id,
                        b_members.c.members_name == group_members.c.group_name,
                        expanded_member.name == group_members.c.members_name,
                        expanded_member.name == member_name,
                        )
                    )))

            else:
                qry = (
                    qry
                    .filter(b_members.c.bindings_id == Binding.id)
                    .filter(b_members.c.members_name == member_name)
                    )

            qry = qry.order_by(role.name.asc())

            result = collections.defaultdict(list)

            for role, resource in qry.yield_per(PER_YIELD):
                result[role.name].append(resource.type_name)

            return result.iteritems()

        @classmethod
        def query_access_by_permission(cls,
                                       session,
                                       role_name=None,
                                       permission_name=None,
                                       expand_groups=False,
                                       expand_resources=False):
            """Return all the (Principal, Resource) combinations allowing
            satisfying access via the specified permission.

            Args:
                session (object): Database session.
                permission_name (str): Permission name to query for.
                expand_groups (bool): Whether or not to expand groups.
                expand_resources (bool): Whether or not to expand resources.

            Yields:
                A generator of access tuples.

            Raises:
                ValueError: If neither role nor permission is set.
            """

            expanded_member = aliased(Member)
            direct_member = aliased(Member)
            resource = aliased(Resource)
            descendant = aliased(Resource)
            role = aliased(Role)
            perm = aliased(Permission)
            binding = aliased(Binding)
            ging = aliased(GroupInGroup)

            entities = [
                role.name,
                (descendant.type_name
                 if expand_resources
                 else resource.type_name),
                expanded_member.name if expand_groups else direct_member.name,
                ]

            qry = session.query(*entities)
            if role_name:
                qry = (
                    qry
                    .filter(role.name == role_name)
                    )
            elif permission_name:
                qry = (
                    qry
                    .filter(perm.name == permission_name)
                    .filter(role_permissions.c.roles_name ==
                            role.name)
                    .filter(role_permissions.c.permissions_name ==
                            perm.name)
                    )
            else:
                raise ValueError('Either role or permission must be set')

            qry = (
                qry
                .filter(binding_members.c.bindings_id == binding.id)
                .filter(binding_members.c.members_name == direct_member.name)
                .filter(resource.type_name == binding.resource_type_name)
                .filter(binding.role_name == role.name)
                )

            if expand_resources:
                qry = (
                    qry
                    .filter(
                        descendant.full_name.startswith(resource.full_name))
                    )

            if expand_groups:
                qry = (
                    qry
                    .filter(
                        ging.parent == direct_member.name,
                        ging.member == group_members.c.group_name,
                        group_members.c.members_name == expanded_member.name,
                        )
                    )

            qry = (
                qry
                .order_by(entities[1].asc(), binding.role_name.asc())
                .distinct()
                )

            cur_role_name = None
            cur_res_name = None
            cur_members = set()
            for r_name, res_name, member_name in qry.yield_per(PER_YIELD):
                if r_name == cur_role_name and cur_res_name == res_name:
                    cur_members.add(member_name)
                else:
                    if cur_role_name:
                        yield cur_role_name, cur_res_name, cur_members
                    cur_role_name = r_name
                    cur_res_name = res_name
                    cur_members = set([member_name])
            if cur_role_name:
                yield cur_role_name, cur_res_name, cur_members

        @classmethod
        def query_access_by_resource(cls, session, resource_type_name,
                                     permission_names, expand_groups=False):
            """Return members who have access to the given resource."""

            member = aliased(Member)
            role = aliased(Role)
            binding = aliased(Binding)
            parent = aliased(Resource)
            child = aliased(Resource)
            direct_member = aliased(Member)
            ging = aliased(GroupInGroup)

            role_names = [
                r.name
                for r in
                cls.get_roles_by_permission_names(session, permission_names)]

            qry = (
                session.query(role.name, member.name)

                # Find the resource requested access for
                .filter(child.type_name == resource_type_name)

                # Map all the ancestors to the corresponding bindings
                .filter(child.full_name.startswith(parent.full_name))
                .filter(binding.resource_type_name == parent.type_name)

                # Map role and bindings together
                .filter(binding.role_name == role.name)

                # Map permission_names to roles covering the permissions
                .filter(role.name.in_(role_names))
                )

            if expand_groups:
                qry = (
                    qry
                    .filter(binding.id == binding_members.c.bindings_id)
                    .filter(direct_member.name ==
                            binding_members.c.members_name)
                    .filter(direct_member.name == ging.parent)
                    .filter(ging.member == group_members.c.group_name)
                    .filter(member.name == group_members.c.members_name)
                    )
            else:
                qry = (
                    qry
                    .filter(binding.id == binding_members.c.bindings_id)
                    .filter(member.name == binding_members.c.members_name)
                    )

            qry = qry.distinct()
            role_members = collections.defaultdict(set)
            for role_name, member_name in qry.yield_per(PER_YIELD):
                role_members[role_name].add(member_name)
            return role_members

        @classmethod
        def query_permissions_by_roles(cls, session, role_names, role_prefixes,
                                       _=1024):
            """Resolve permissions for the role."""

            if not role_names and not role_prefixes:
                raise Exception('No roles or role prefixes specified')

            qry = (
                session.query(Role, Permission)
                .filter(Role.name == role_permissions.c.roles_name)
                .filter(Permission.name == role_permissions.c.permissions_name)
                )

            if role_names:
                qry = qry.filter(Role.name.in_(role_names))

            if role_prefixes:
                qry = qry.filter(
                    or_(*[Role.name.startswith(prefix)
                          for prefix in role_prefixes]))

            return iter(qry.yield_per(PER_YIELD))

        @classmethod
        def denormalize(cls, session):
            """Denormalize the model into access triples."""

            child = aliased(Resource)
            parent = aliased(Resource)
            expanded_member = aliased(Member)
            group_in_group = aliased(Member)
            perm = aliased(Permission)
            role = aliased(Role)

            qry = (
                session.query(perm.name,
                              child.type_name,
                              expanded_member.name,)

                # Connect the Role with the included permission
                .filter(role.name == role_permissions.c.roles_name)
                .filter(perm.name == role_permissions.c.permissions_name)

                # Connect the Role with the binding
                .filter(Binding.role_name == role.name)

                # Connect the Resource with the binding
                .filter(Binding.resource_type_name == parent.type_name)

                # Expand the child resources
                .filter(child.full_name.startswith(parent.full_name))

                # Connect the binding with the member
                .filter(
                    # expanded_member is transitively in a group member
                    and_(
                        # group_member is the direct policy member
                        Binding.id == binding_members.c.bindings_id,

                        # there is a group_in_group that is a binding member
                        binding_members.c.members_name == GroupInGroup.parent,
                        group_in_group.name == GroupInGroup.member,

                        # expanded_member is a direct member of group_in_group
                        group_in_group.name == group_members.c.group_name,
                        expanded_member.name == group_members.c.members_name)))

            return iter(qry.yield_per(PER_YIELD))

        @classmethod
        def set_iam_policy(cls, session, resource_type_name, policy):
            """Sets an IAM policy for the resource."""

            old_policy = cls.get_iam_policy(session, resource_type_name)
            if policy['etag'] != old_policy['etag']:
                raise Exception(
                    'Etags distinct, stored={}, provided={}'.format(
                        old_policy['etag'], policy['etag']))

            old_policy = old_policy['bindings']
            policy = policy['bindings']

            def filter_etag(policy):
                """Filter etag key/value out of policy map."""

                return {k: v for k, v in policy.iteritems() if k != 'etag'}

            def calculate_diff(policy, old_policy):
                """Calculate the grant/revoke difference between policies."""

                diff = collections.defaultdict(list)
                for role, members in filter_etag(policy).iteritems():
                    if role in old_policy:
                        for member in members:
                            if member not in old_policy[role]:
                                diff[role].append(member)
                    else:
                        diff[role] = members
                return diff

            grants = calculate_diff(policy, old_policy)
            revocations = calculate_diff(old_policy, policy)

            for role, members in revocations.iteritems():
                bindings = (
                    session.query(Binding)
                    .filter(Binding.resource_type_name == resource_type_name)
                    .filter(Binding.role_name == role)
                    .join(binding_members).join(Member)
                    .filter(Member.name.in_(members)).all())

                for binding in bindings:
                    session.delete(binding)
            for role, members in grants.iteritems():
                inserted = False
                existing_bindings = (
                    session.query(Binding)
                    .filter(Binding.resource_type_name == resource_type_name)
                    .filter(Binding.role_name == role).all())

                for binding in existing_bindings:
                    if binding.role_name == role:
                        inserted = True
                        for member in members:
                            binding.members.append(
                                session.query(Member).filter(
                                    Member.name == member).one())
                if not inserted:
                    binding = Binding(
                        resource_type_name=resource_type_name,
                        role=session.query(Role).filter(
                            Role.name == role).one())
                    binding.members = session.query(Member).filter(
                        Member.name.in_(members)).all()
                    session.add(binding)
            resource = session.query(Resource).filter(
                Resource.type_name == resource_type_name).one()
            resource.increment_update_counter()
            session.commit()

        @classmethod
        def get_iam_policy(cls, session, resource_type_name):
            """Return the IAM policy for a resource."""

            resource = session.query(Resource).filter(
                Resource.type_name == resource_type_name).one()
            policy = {
                'etag': resource.get_etag(),
                'bindings': {},
                'resource': resource.type_name}
            for binding in (session.query(Binding)
                            .filter(Binding.resource_type_name ==
                                    resource_type_name)
                            .all()):
                role = binding.role_name
                members = [m.name for m in binding.members]
                policy['bindings'][role] = members
            return policy

        @classmethod
        def check_iam_policy(cls, session, resource_type_name, permission_name,
                             member_name):
            """Check access according to the resource IAM policy."""

            child = aliased(Resource)
            parent = aliased(Resource)
            binding = aliased(Binding)
            expanded = aliased(Member)
            direct = aliased(Member)
            ging = aliased(GroupInGroup)
            role = aliased(Role)

            qry = (
                session.query(Permission.name)

                # Search for the triple
                .filter(Permission.name == permission_name)
                .filter(child.type_name == resource_type_name)
                .filter(expanded.name == member_name)

                # Connect role, binding & resource
                .filter(child.full_name.startswith(parent.full_name))
                .filter(binding.resource_type_name == parent.type_name)
                .filter(binding.role_name == role.name)

                # Connect role and permission
                .filter(role.name == role_permissions.c.roles_name)
                .filter(Permission.name == role_permissions.c.permissions_name)

                # Lookup resource hierarchy
                .filter(binding.id == binding_members.c.bindings_id)
                .filter(direct.name == binding_members.c.members_name)
                .filter(ging.parent == direct.name)
                .filter(ging.member == group_members.c.group_name)
                .filter(expanded.name == group_members.c.members_name)
                )

            return qry.first() is not None

        @classmethod
        def list_roles_by_prefix(cls, session, role_prefix):
            """Provides a list of roles matched via name prefix."""

            qry = (
                session.query(Role.name)
                .filter(Role.name.startswith(role_prefix))
                )

            return iter([n for (n,) in qry.yield_per(PER_YIELD)])

        @classmethod
        def add_role_by_name(cls, session, role_name, permission_names):
            """Creates a new role."""

            permission_names = set(permission_names)
            existing_permissions = session.query(Permission).filter(
                Permission.name.in_(permission_names)).all()
            for existing_permission in existing_permissions:
                try:
                    permission_names.remove(existing_permission.name)
                except KeyError:
                    pass

            new_permissions = [Permission(name=n) for n in permission_names]
            for perm in new_permissions:
                session.add(perm)
            cls.add_role(session, role_name,
                         existing_permissions + new_permissions)
            session.commit()

        @classmethod
        def del_role_by_name(cls, session, role_name):
            """Deletes a role by name."""

            session.query(Role).filter(Role.name == role_name).delete()
            role_permission_delete = role_permissions.delete(
                role_permissions.c.roles_name == role_name)
            session.execute(role_permission_delete)
            session.commit()

        @classmethod
        def add_group_member(cls,
                             session,
                             member_type_name,
                             parent_type_names,
                             denorm=True):
            """Add member, optionally with parent relationship."""

            cls.add_member(session,
                           member_type_name,
                           parent_type_names,
                           denorm)
            session.commit()

        @classmethod
        def del_group_member(cls, session, member_type_name, parent_type_name,
                             only_delete_relationship, denorm=True):
            """Delete member."""

            if only_delete_relationship:
                group_members_delete = group_members.delete(
                    and_(group_members.c.members_name == member_type_name,
                         group_members.c.group_name == parent_type_name))
                session.execute(group_members_delete)
            else:
                (session.query(Member)
                 .filter(Member.name == member_type_name)
                 .delete())
                group_members_delete = group_members.delete(
                    group_members.c.members_name == member_type_name)
                session.execute(group_members_delete)
            session.commit()
            if denorm:
                cls.denorm_group_in_group(session)

        @classmethod
        def list_group_members(cls, session, member_name_prefix):
            """Returns members filtered by prefix."""

            qry = (
                session.query(Member)
                .filter(Member.member_name.startswith(member_name_prefix))
                )

            return [m.name for m in qry.yield_per(PER_YIELD)]

        @classmethod
        def iter_resources_by_prefix(cls,
                                     session,
                                     full_resource_name_prefix=None,
                                     type_name_prefix=None,
                                     type_prefix=None,
                                     name_prefix=None):
            """Returns iterator to resources filtered by prefix."""

            if not any([arg is not None for arg in [full_resource_name_prefix,
                                                    type_name_prefix,
                                                    type_prefix,
                                                    name_prefix]]):
                raise Exception('At least one prefix must be set')

            qry = session.query(Resource)
            if full_resource_name_prefix:
                qry = qry.filter(Resource.full_name.startswith(
                    full_resource_name_prefix))
            if type_name_prefix:
                qry = qry.filter(Resource.type_name.startswith(
                    type_name_prefix))
            if type_prefix:
                qry = qry.filter(Resource.type.startswith(
                    type_prefix))
            if name_prefix:
                qry = qry.filter(Resource.name.startswith(
                    name_prefix))

            return iter(qry.yield_per(PER_YIELD))

        @classmethod
        def list_resources_by_prefix(cls,
                                     session,
                                     full_resource_name_prefix=None,
                                     type_name_prefix=None,
                                     type_prefix=None,
                                     name_prefix=None):
            """Returns resources filtered by prefix."""

            return list(
                cls.iter_resources_by_prefix(session,
                                             full_resource_name_prefix,
                                             type_name_prefix,
                                             type_prefix,
                                             name_prefix))

        @classmethod
        def del_resource_by_name(cls, session, resource_type_name):
            """Deletes a resource specified via full name."""

            resource = (
                session.query(Resource)
                .filter(Resource.type_name == resource_type_name).one())

            # Find all children
            res_qry = (
                session.query(Resource)
                .filter(Resource.full_name.startswith(resource.full_name)))

            res_type_names = [r.type_name for r in res_qry.yield_per(1024)]
            binding_qry = (
                session.query(Binding)
                .filter(Binding.resource_type_name.in_(res_type_names)))

            binding_qry.delete(synchronize_session='fetch')
            res_qry.delete(synchronize_session='fetch')

            session.commit()

        @classmethod
        def add_resource_by_name(cls,
                                 session,
                                 resource_type_name,
                                 parent_type_name,
                                 no_require_parent):
            """Adds resource specified via full name."""

            if not no_require_parent:
                parent = session.query(Resource).filter(
                    Resource.type_name == parent_type_name).one()
            else:
                parent = None
            return cls.add_resource(session, resource_type_name, parent)

        @classmethod
        def add_resource(cls, session, resource_type_name, parent=None):
            """Adds resource by name."""

            res_type, res_name = resource_type_name.split('/')
            parent_full_resource_name = (
                '' if parent is None else parent.full_name)

            full_resource_name = to_full_resource_name(
                parent_full_resource_name,
                resource_type_name)

            resource = Resource(full_name=full_resource_name,
                                type_name=resource_type_name,
                                name=res_name,
                                type=res_type,
                                parent=parent)
            session.add(resource)
            return resource

        @classmethod
        def add_role(cls, session, name, permissions=None):
            """Add role by name."""

            permissions = [] if permissions is None else permissions
            role = Role(name=name, permissions=permissions)
            session.add(role)
            return role

        @classmethod
        def add_permission(cls, session, name, roles=None):
            """Add permission by name."""

            roles = [] if roles is None else roles
            permission = Permission(name=name, roles=roles)
            session.add(permission)
            return permission

        @classmethod
        def add_binding(cls, session, resource, role, members):
            """Add a binding to the model."""

            binding = Binding(resource=resource, role=role, members=members)
            session.add(binding)
            return binding

        @classmethod
        def add_member(cls,
                       session,
                       type_name,
                       parent_type_names=None,
                       denorm=False):
            """Add a member to the model."""

            if not parent_type_names:
                parent_type_names = []
            res_type, name = type_name.split('/', 1)
            parents = session.query(Member).filter(
                Member.name.in_(parent_type_names)).all()
            if len(parents) != len(parent_type_names):
                msg = 'parents: {}, expected: {}'.format(
                    parents, parent_type_names)
                raise Exception('Parent not found, {}'.format(msg))

            member = Member(name=type_name,
                            member_name=name,
                            type=res_type,
                            parents=parents)
            session.add(member)
            session.commit()
            if denorm and res_type == 'group' and parents:
                cls.denorm_group_in_group(session)
            return member

        @classmethod
        def expand_resources_by_type_names(cls, session, res_type_names):
            """Expand resources by type/name format.

                Returns: {res_type_name: Expansion(res_type_name), ... }
            """

            res_key = aliased(Resource, name='res_key')
            res_values = aliased(Resource, name='res_values')

            expressions = []
            for res_type_name in res_type_names:
                expressions.append(and_(
                    res_key.type_name == res_type_name))

            res = (
                session.query(res_key, res_values)
                .filter(res_key.type_name.in_(res_type_names))
                .filter(res_values.full_name.startswith(
                    res_key.full_name)).yield_per(1024))

            mapping = collections.defaultdict(set)
            for k, value in res:
                mapping[k].add(value)
            return mapping

        @classmethod
        def expand_resources_by_names(cls, session, res_type_names):
            """Expand resources by type/name format."""

            child = aliased(Resource)
            parent = aliased(Resource)
            qry = (
                session.query(child)
                .filter(parent.type_name.in_(res_type_names))
                .filter(child.full_name.startswith(parent.full_name))
                )

            return [res.full_name for res in qry.yield_per(PER_YIELD)]

        @classmethod
        def expand_resources(cls, session, full_resource_names):
            """Expand resources towards the bottom."""

            if (not isinstance(full_resource_names, list) and
                    not isinstance(full_resource_names, set)):
                raise TypeError('full_resource_names must be list or set')

            child = aliased(Resource)
            parent = aliased(Resource)
            qry = (
                session.query(child)
                .filter(parent.full_name.in_(full_resource_names))
                .filter(child.full_name.startswith(parent.full_name))
                )

            return [res.full_name for res in qry.yield_per(PER_YIELD)]

        @classmethod
        def reverse_expand_members(cls, session, member_names,
                                   request_graph=False):
            """Expand members to their groups."""

            child = aliased(Member)
            parent = aliased(Member)
            reverse_expanded = aliased(Member)
            ging = aliased(GroupInGroup)
            group_member2 = aliased(group_members)

            qry = (
                session.query(parent)
                .filter(child.name.in_(member_names))
                .filter(ging.parent == parent.name)
                .filter(ging.member == group_members.c.group_name)
                .filter(group_members.c.members_name == child.name)
                .distinct()
                )

            member_set = set()
            for item in qry.yield_per(PER_YIELD):
                member_set.add(item)

            if request_graph:
                qry = (
                    session.query(parent, reverse_expanded)
                    .filter(child.name.in_(member_names))
                    .filter(ging.parent == reverse_expanded.name)
                    .filter(ging.member == group_members.c.group_name)
                    .filter(child.name == group_members.c.members_name)
                    .filter(parent.name == group_member2.c.group_name)
                    .filter(reverse_expanded.name ==
                            group_member2.c.members_name)
                    .filter(parent.name != reverse_expanded.name)
                    .distinct()
                    )

                membership_graph = collections.defaultdict(set)
                for parent, child in qry.yield_per(PER_YIELD):
                    membership_graph[child.name].add(parent.name)
                return member_set, membership_graph
            return member_set

        @classmethod
        def resource_ancestors(cls, session, resource_type_names):
            """Resolve the transitive ancestors by type/name format.

            Algorithm:
            1. Find resources specified in input
            2. Fina all ancestors including 1. themselves
            3. For all of 2., find their direct parent if any
            4. Build map<Parent, set<Child>>
            """

            child = aliased(Resource)
            parent = aliased(Resource)
            ancestor = aliased(Resource)
            qry = (
                session.query(parent.type_name, ancestor.type_name)
                .filter(child.type_name.in_(resource_type_names))
                .filter(child.full_name.startswith(ancestor.full_name))
                .filter(parent.type_name == ancestor.parent_type_name)
                )

            result = collections.defaultdict(set)
            for parent, child in qry.yield_per(PER_YIELD):
                result[parent].add(child)
            return result

        @classmethod
        def find_resource_path(cls, session, resource_type_name):
            """Find resource ancestors by type/name format."""

            parent = aliased(Resource)
            child = aliased(Resource)

            qry = (
                session.query(parent)
                .filter(child.type_name == resource_type_name)
                .filter(child.full_name.startswith(parent.full_name))
                .order_by(parent.full_name.desc())
                )

            return qry.all()

        @classmethod
        def get_roles_by_permission_names(cls, session, permission_names):
            """Return the list of roles covering the specified permissions."""

            # All roles contain a superset of the empty permission set
            if not permission_names:
                return iter(session.query(Role).yield_per(PER_YIELD))

            # Each role will contain a superset of permission_names
            qry = (
                session.query(Role)
                .filter(Role.name == role_permissions.c.roles_name)
                .filter(Permission.name == role_permissions.c.permissions_name)
                .filter(Permission.name.in_(permission_names))
                .group_by(Role)
                .having(func.count(Permission.name) == len(permission_names))
                )

            return iter(qry.yield_per(PER_YIELD))

        @classmethod
        def get_member(cls, session, name):
            """Get member by name."""

            qry = (
                session.query(Member)
                .filter(Member.name == name)
                )
            return qry.yield_per(PER_YIELD).all()

    base.metadata.create_all(dbengine)
    return sessionmaker(bind=dbengine), ModelAccess


def undefine_model(session_maker, data_access):
    """Deletes an entire model and the corresponding data in the database."""

    session = session_maker()
    data_access.delete_all(session)

LOCK = Lock()


class ModelManager(object):
    """The Central class to create,list,get and delete models.

        ModelManager is mostly used to do the lookup from model name to the
        session cache which is given in each client's request.
    """

    def __init__(self, dbengine):
        self.engine = dbengine
        self.modelmaker = self._create_model_session()
        self.sessionmakers = {}

    def _create_model_session(self):
        """Create a session to read from the models table."""

        MODEL_BASE.metadata.create_all(self.engine)
        return db.ScopedSessionMaker(
            sessionmaker(
                bind=self.engine),
            auto_commit=True)

    @mutual_exclusive(LOCK)
    def create(self, name):
        """Create a new model entry in the database."""

        handle = generate_model_handle()
        with self.modelmaker() as session:
            model = Model(
                handle=handle,
                name=name,
                state="CREATED",
                created_at=datetime.datetime.utcnow(),
                watchdog_timer=datetime.datetime.utcnow(),
                etag_seed=generate_model_seed())
            session.add(model)
            self.sessionmakers[model.handle] = define_model(
                model.handle, self.engine, model.etag_seed)
            return handle

    def get(self, model):
        """Get model data by name."""

        session_maker, data_access = self._get(model)
        return db.ScopedSession(session_maker()), data_access

    def _get(self, handle):
        """Get model data by name internal."""

        if handle not in [m.handle for m in self.models()]:
            raise KeyError('handle={}, available={}'.format(
                handle,
                [m.handle for m in self.models()]))
        try:
            return self.sessionmakers[handle]
        except KeyError:
            with self.modelmaker() as session:
                model = (session.query(Model)
                         .filter(Model.handle == handle)
                         .one())
                self.sessionmakers[model.handle] = define_model(
                    model.handle, self.engine, model.etag_seed)
                return self.sessionmakers[model.handle]

    @mutual_exclusive(LOCK)
    def delete(self, model_name):
        """Delete a model entry in the database by name."""

        _, data_access = self._get(model_name)
        if model_name in self.sessionmakers:
            del self.sessionmakers[model_name]
        with self.modelmaker() as session:
            session.query(Model).filter(Model.handle == model_name).delete()
        data_access.delete_all(self.engine)

    def _models(self, expunge=False):
        """Return the list of models from the database."""

        with self.modelmaker() as session:
            items = session.query(Model).all()
            if expunge:
                session.expunge_all()
            return items

    def models(self):
        """Expunging wrapper for _models."""
        return self._models(expunge=True)

    def model(self, model_name, expunge=True, session=None):
        """Get model from database by name."""

        def instantiate_model(session, model_name, expunge):
            """Creates a model object by querying the database.

            Args:
                session (object): Database session.
                model_name (str): Model name to instantiate.
                expunge (bool): Whether or not to detach the object from
                                the session for use in another session.
            """

            item = session.query(Model).filter(
                Model.handle == model_name).one()
            if expunge:
                session.expunge(item)
            return item

        if not session:
            with self.modelmaker() as scoped_session:
                return instantiate_model(scoped_session, model_name, expunge)
        else:
            return instantiate_model(session, model_name, expunge)


def create_engine(*args,
                  **kwargs):
    """Create engine wrapper to patch database options.

    Args:
        *args (list): Arguments.
        **kwargs (dict): Arguments.

    Returns:
        object: Engine.
    """

    sqlite_enforce_fks = 'sqlite_enforce_fks'
    forward_kwargs = {k: v for k, v in kwargs.iteritems()}
    if sqlite_enforce_fks in forward_kwargs:
        del forward_kwargs[sqlite_enforce_fks]

    engine = sqlalchemy_create_engine(*args, **forward_kwargs)
    dialect = engine.dialect.name
    if dialect == 'sqlite':
        @event.listens_for(engine, "connect")
        def do_connect(dbapi_connection, _):
            """Hooking database connect.

            Args:
                dbapi_connection (object): Database connection.
                _ (object): Unknown.
            """
            # Fix for nested transaction problems
            dbapi_connection.isolation_level = None
            if kwargs.get(sqlite_enforce_fks, False):
                # Enable foreign key constraints
                dbapi_connection.execute('pragma foreign_keys=ON')

        @event.listens_for(engine, "begin")
        def do_begin(conn):
            """Hooking database transaction begin.

            Args:
                conn (object): Database connection.
            """
            # Fix for nested transaction problems
            conn.execute("BEGIN")

        engine.__explain_hooks = [do_connect, do_begin] # pylint: disable=protected-access

    return engine


def session_creator(model_name, filename=None, seed=None, echo=False):
    """Create a session maker for the model and db file."""

    if filename:
        engine = create_engine('sqlite:///{}'.format(filename),
                               pool_recycle=POOL_RECYCLE_SECONDS)
    else:
        engine = create_engine('sqlite:///:memory:',
                               pool_recycle=POOL_RECYCLE_SECONDS, echo=echo)
    if seed is None:
        seed = generate_model_seed()
    session_maker, data_access = define_model(model_name, engine, seed)
    return session_maker, data_access
