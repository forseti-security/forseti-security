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

""" Database abstraction objects for IAM Explain. """

# pylint: disable=too-many-lines,singleton-comparison

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
from sqlalchemy import not_
from sqlalchemy.orm import relationship
from sqlalchemy.orm import aliased
from sqlalchemy.orm import sessionmaker
from sqlalchemy.sql import select
from sqlalchemy.sql import union
from sqlalchemy.ext.declarative import declarative_base

from google.cloud.forseti.services.utils import mutual_exclusive
from google.cloud.forseti.services.utils import to_full_resource_name
from google.cloud.forseti.services import db
from google.cloud.forseti.services.utils import get_sql_dialect

# TODO: The next editor must remove this disable and correct issues.
# pylint: disable=missing-type-doc,missing-return-type-doc,missing-return-doc
# pylint: disable=missing-param-doc,missing-raises-doc,missing-yield-doc
# pylint: disable=missing-yield-type-doc,too-many-branches

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
    """IAM Explain model object in database."""

    __tablename__ = 'model'
    name = Column(String(32), primary_key=True)
    handle = Column(String(32))
    state = Column(String(32))
    watchdog_timer = Column(DateTime)
    created_at = Column(DateTime)
    etag_seed = Column(String(32), nullable=False)
    message = Column(Text())
    warnings = Column(Text())

    # Non-SQL attributes
    warning_store = list()

    def kick_watchdog(self):
        """Used during import to notify the import is still progressing."""

        self.watchdog_timer = datetime.datetime.utcnow()

    def add_warning(self, warning):
        """Add a warning to the model.

        Args:
            warning (str): Warning message
        """
        self.warning_store.append(warning)

    def get_warnings(self):
        """Returns any stored warnings."""
        return '\n'.join(self.warning_store)

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

    Resource.children = relationship(
        "Resource", order_by=Resource.full_name, back_populates="parent")

    class Member(base):
        """Row entry for a policy member."""

        __tablename__ = members_tablename
        name = Column(String(256), primary_key=True)
        type = Column(String(64))
        member_name = Column(String(128))

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

    class Permission(base):
        """Row entry for an IAM permission."""

        __tablename__ = permissions_tablename
        name = Column(String(128), primary_key=True)
        roles = relationship('Role',
                             secondary=role_permissions,
                             back_populates='permissions')

        def __repr__(self):
            return "<Permission(name='%s')>" % (self.name)

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
                    '`{}`'.format(group_members.name)]
                lock_stmts = ['{} WRITE'.format(tbl) for tbl in locked_tables]
                query = 'LOCK TABLES {}'.format(', '.join(lock_stmts))
                session.execute(query)
            try:
                # Remove all existing rows in the denormalization
                session.execute(GroupInGroup.__table__.delete())

                # Select member relation into GroupInGroup
                qry = (
                    GroupInGroup.__table__.insert()
                    .from_select(
                        ['parent', 'member'],
                        group_members.select()
                        .where(
                            group_members.c.group_name.startswith('group/')
                            )
                        .where(
                            group_members.c.members_name.startswith('group/')
                            )
                        )
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
                            role, permission):
            """Provide info about how the member has access to the resource."""
            members, member_graph = cls.reverse_expand_members(
                session, [member_name], request_graph=True)
            member_names = [m.name for m in members]
            resource_type_names = [r.type_name for r in
                                   cls.find_resource_path(session,
                                                          resource_type_name)]

            if role:
                roles = set([role])
                qry = session.query(Binding, Member).join(
                    binding_members).join(Member)
            else:
                roles = [r.name for r in
                         cls.get_roles_by_permission_names(
                             session,
                             [permission])]
                qry = session.query(Binding, Member)
                qry = qry.join(binding_members).join(Member)
                qry = qry.join(Role).join(role_permissions).join(Permission)

            qry = qry.filter(Binding.role_name.in_(roles))
            qry = qry.filter(Member.name.in_(member_names))
            qry = qry.filter(
                Binding.resource_type_name.in_(resource_type_names))
            result = qry.all()
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

            for resource in qry.yield_per(PER_YIELD):
                yield resource

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

            if reverse_expand_members:
                member_names = [m.name for m in
                                cls.reverse_expand_members(
                                    session,
                                    [member_name], False)]
            else:
                member_names = [member_name]

            roles = cls.get_roles_by_permission_names(
                session, permission_names)

            qry = (
                session.query(Binding)
                .join(binding_members)
                .join(Member)
                .filter(Binding.role_name.in_([r.name for r in roles]))
                .filter(Member.name.in_(member_names)))

            bindings = qry.yield_per(1024)
            if not expand_resources:
                return [(binding.role_name,
                         [binding.resource_type_name]) for binding in bindings]

            r_type_names = [binding.resource_type_name for binding in bindings]
            expansion = cls.expand_resources_by_type_names(
                session,
                r_type_names)

            res_exp = {k.type_name:
                       [v.type_name for v in values]
                       for k, values in expansion.iteritems()}

            return [(binding.role_name,
                     res_exp[binding.resource_type_name])
                    for binding in bindings]

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

            if role_name:
                role_names = [role_name]
            elif permission_name:
                role_names = [p.name for p in
                              cls.get_roles_by_permission_names(
                                  session,
                                  [permission_name])]
            else:
                raise ValueError('Either role or permission must be set')

            if expand_resources:
                expanded_resources = aliased(Resource)
                qry = (
                    session.query(expanded_resources, Binding, Member)
                    .filter(binding_members.c.bindings_id == Binding.id)
                    .filter(binding_members.c.members_name == Member.name)
                    .filter(expanded_resources.full_name.startswith(
                        Resource.full_name))
                    .filter(Resource.type_name == Binding.resource_type_name)
                    .filter(Binding.role_name.in_(role_names)))
            else:
                qry = (
                    session.query(Resource, Binding, Member)
                    .filter(binding_members.c.bindings_id == Binding.id)
                    .filter(binding_members.c.members_name == Member.name)
                    .filter(Resource.type_name == Binding.resource_type_name)
                    .filter(Binding.role_name.in_(role_names)))

            qry = qry.order_by(Resource.name.asc(), Binding.role_name.asc())

            if expand_groups:
                to_expand = set([m.name for _, _, m in
                                 qry.yield_per(PER_YIELD)])
                expansion = cls.expand_members_map(session,
                                                   to_expand,
                                                   show_group_members=False,
                                                   member_contain_self=True)

            qry = qry.distinct()

            cur_resource = None
            cur_role = None
            cur_members = set()
            for resource, binding, member in qry.yield_per(PER_YIELD):
                if cur_resource != resource.type_name:
                    if cur_resource is not None:
                        yield cur_role, cur_resource, cur_members
                    cur_resource = resource.type_name
                    cur_role = binding.role_name
                    cur_members = set()
                if expand_groups:
                    for member_name in expansion[member.name]:
                        cur_members.add(member_name)
                else:
                    cur_members.add(member.name)
            if cur_resource is not None:
                yield cur_role, cur_resource, cur_members

        @classmethod
        def query_access_by_resource(cls, session, resource_type_name,
                                     permission_names, expand_groups=False):
            """Return members who have access to the given resource."""

            roles = cls.get_roles_by_permission_names(
                session, permission_names)
            resources = cls.find_resource_path(session, resource_type_name)

            res = (session.query(Binding, Member)
                   .filter(
                       Binding.role_name.in_([r.name for r in roles]),
                       Binding.resource_type_name.in_(
                           [r.type_name for r in resources]))
                   .join(binding_members).join(Member))

            role_member_mapping = collections.defaultdict(set)
            for binding, member in res:
                role_member_mapping[binding.role_name].add(member.name)

            if expand_groups:
                for role in role_member_mapping:
                    role_member_mapping[role] = (
                        [m.name for m in cls.expand_members(
                            session,
                            role_member_mapping[role])])

            return role_member_mapping

        @classmethod
        def query_permissions_by_roles(cls, session, role_names, role_prefixes,
                                       _=1024):
            """Resolve permissions for the role."""

            if not role_names and not role_prefixes:
                raise Exception('No roles or role prefixes specified')
            qry = session.query(Role, Permission).join(
                role_permissions).join(Permission)
            if role_names:
                qry = qry.filter(Role.name.in_(role_names))
            if role_prefixes:
                qry = qry.filter(
                    or_(*[Role.name.startswith(prefix)
                          for prefix in role_prefixes]))
            return qry.all()

        @classmethod
        def denormalize(cls, session):
            """Denormalize the model into access triples."""

            qry = (session.query(Binding)
                   .join(binding_members)
                   .join(Member))

            members = set()
            for binding in qry.yield_per(PER_YIELD):
                for member in binding.members:
                    members.add(member.name)

            expanded_members = cls.expand_members_map(session, members)
            role_permissions_map = collections.defaultdict(set)

            qry = (session.query(Role, Permission)
                   .join(role_permissions)
                   .filter(
                       Role.name == role_permissions.c.roles_name)
                   .filter(
                       Permission.name == role_permissions.c.permissions_name))

            for role, permission in qry.yield_per(PER_YIELD):
                role_permissions_map[role.name].add(permission.name)

            for binding, member in (
                    session.query(Binding, Member)
                    .join(binding_members)
                    .filter(binding_members.c.bindings_id == Binding.id)
                    .filter(binding_members.c.members_name == Member.name)
                    .yield_per(PER_YIELD)):

                resource_type_name = binding.resource_type_name
                resource_mapping = cls.expand_resources_by_type_names(
                    session,
                    [resource_type_name])

                resource_mapping = {k.type_name: set([m.type_name for m in v])
                                    for k, v in resource_mapping.iteritems()}

                for expanded_member in expanded_members[member.name]:
                    for permission in role_permissions_map[binding.role_name]:
                        for res in resource_mapping[resource_type_name]:
                            triple = (permission, res, expanded_member)
                            yield triple

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

            member_names = [m.name for m in
                            cls.reverse_expand_members(
                                session,
                                [member_name])]
            resource_type_names = [r.type_name for r in cls.find_resource_path(
                session,
                resource_type_name)]

            if not member_names:
                raise Exception('Member not found: {}'.
                                format(member_name))
            if not resource_type_names:
                raise Exception('Resource not found: {}'.
                                format(resource_type_name))

            return (
                session.query(Permission)
                .filter(Permission.name == permission_name)
                .join(role_permissions).join(Role).join(Binding)
                .filter(Binding.resource_type_name.in_(resource_type_names))
                .join(binding_members).join(Member)
                .filter(Member.name.in_(member_names)).first() is not None)

        @classmethod
        def list_roles_by_prefix(cls, session, role_prefix):
            """Provides a list of roles matched via name prefix."""

            return [r.name for r in session.query(Role)
                    .filter(Role.name.startswith(role_prefix)).all()]

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
                             denorm=False):
            """Add member, optionally with parent relationship."""

            cls.add_member(session,
                           member_type_name,
                           parent_type_names,
                           denorm)
            session.commit()

        @classmethod
        def del_group_member(cls, session, member_type_name, parent_type_name,
                             only_delete_relationship, denorm=False):
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

            return [m.name for m in session.query(Member).filter(
                Member.member_name.startswith(member_name_prefix)).all()]

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

            for resource in qry.yield_per(1024):
                yield resource

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
            res_qry = (session.query(Resource)
                       .filter(Resource.full_name.startswith(
                           resource.full_name)))

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

            qry = (
                session.query(Resource)
                .filter(Resource.type_name.in_(res_type_names))
                )

            full_resource_names = [r.full_name for r in qry.all()]
            return cls.expand_resources(session, full_resource_names)

        @classmethod
        def expand_resources(cls, session, full_resource_names):
            """Expand resources towards the bottom."""

            if (not isinstance(full_resource_names, list) and
                    not isinstance(full_resource_names, set)):
                raise TypeError('full_resource_names must be list or set')

            resources = session.query(Resource).filter(
                Resource.full_name.in_(full_resource_names)).all()

            new_resource_set = set(resources)
            resource_set = set(resources)

            def add_to_sets(resources):
                """Adds resources to the sets."""

                for resource in resources:
                    if resource not in resource_set:
                        new_resource_set.add(resource)
                        resource_set.add(resource)

            while new_resource_set:
                resources_to_walk = new_resource_set
                new_resource_set = set()
                for resource in resources_to_walk:
                    add_to_sets(resource.children)

            return [r.full_name for r in resource_set]

        @classmethod
        def reverse_expand_members(cls, session, member_names,
                                   request_graph=False):
            """Expand members to their groups."""

            members = session.query(Member).filter(
                Member.name.in_(member_names)).all()
            membership_graph = collections.defaultdict(set)
            member_set = set()
            new_member_set = set()

            def add_to_sets(members, child):
                """Adds the members & children to the sets."""

                for member in members:
                    if request_graph and child:
                        membership_graph[child.name].add(member.name)
                    if request_graph and not child:
                        if member.name not in membership_graph:
                            membership_graph[member.name] = set()
                    if member not in member_set:
                        new_member_set.add(member)
                        member_set.add(member)

            add_to_sets(members, None)
            while new_member_set:
                members_to_walk = new_member_set
                new_member_set = set()
                for member in members_to_walk:
                    add_to_sets(member.parents, member)

            if request_graph:
                return member_set, membership_graph
            return member_set

        @classmethod
        def expand_members_map(cls,
                               session,
                               member_names,
                               show_group_members=True,
                               member_contain_self=True):
            """Expand group membership keyed by member.

            Args:
                member_names (set): Member names to expand
                show_group_members (bool): Whether to include subgroups
                member_contain_self (bool): Whether to include a parent
                                            as its own member
            Returns:
                dict: <Member, set(Children).
            """

            def separate_groups(member_names):
                """Separate groups and other members in two lists."""
                groups = []
                others = []
                for name in member_names:
                    if name.startswith('group/'):
                        groups.append(name)
                    else:
                        others.append(name)
                return groups, others

            selectables = []
            group_names, other_names = separate_groups(member_names)

            t_ging = GroupInGroup.__table__
            t_members = group_members

            transitive_membership = (
                # This resolves groups to its transitive non-group members
                select([t_ging.c.parent, t_members.c.members_name])
                .select_from(
                    t_ging.join(t_members,
                                t_ging.c.member == t_members.c.group_name))
                ).where(t_ging.c.parent.in_(group_names))
            if not show_group_members:
                transitive_membership = transitive_membership.where(
                    not_(t_members.c.members_name.startswith('group/')))

            selectables.append(
                transitive_membership.alias('transitive_membership'))

            direct_membership = (
                select([t_members.c.group_name, t_members.c.members_name])
                .where(t_members.c.group_name.in_(group_names)))
            if not show_group_members:
                direct_membership = direct_membership.where(
                    not_(t_members.c.members_name.startswith('group/')))

            selectables.append(
                direct_membership.alias('direct_membership'))

            if show_group_members:
                # Show groups as members of other groups
                group_in_groups = (
                    select([t_ging.c.parent, t_ging.c.member])
                    .where(t_ging.c.parent.in_(group_names))
                    )
                selectables.append(
                    group_in_groups.alias('group_in_groups'))

            # Union all the queries
            qry = union(*selectables)

            # Build the result dict
            result = collections.defaultdict(set)
            for parent, child in session.execute(qry):
                result[parent].add(child)
            for parent in other_names:
                result[parent] = set()

            # Add each parent as its own member
            if member_contain_self:
                for name in member_names:
                    result[name].add(name)
            return result

        @classmethod
        def expand_members(cls, session, member_names):
            """Expand group membership towards the members."""

            members = session.query(Member).filter(
                Member.name.in_(member_names)).all()

            def is_group(member):
                """Returns true iff the member is a group."""
                return member.type == 'group'

            group_set = set()
            non_group_set = set()
            new_group_set = set()

            def add_to_sets(members):
                """Adds new members to the sets."""
                for member in members:
                    if is_group(member):
                        if member not in group_set:
                            new_group_set.add(member)
                        group_set.add(member)
                    else:
                        non_group_set.add(member)

            add_to_sets(members)

            while new_group_set:
                groups_to_walk = new_group_set
                new_group_set = set()
                for group in groups_to_walk:
                    add_to_sets(group.children)

            return group_set.union(non_group_set)

        @classmethod
        def resource_ancestors(cls, session, resource_type_names):
            """Resolve the transitive ancestors by type/name format."""

            resource_names = resource_type_names
            resource_graph = collections.defaultdict(set)

            res_childs = aliased(Resource, name='res_childs')
            res_anc = aliased(Resource, name='resource_parent')

            resources_set = set(resource_names)
            resources_new = set(resource_names)

            for resource in resources_new:
                resource_graph[resource] = set()

            while resources_new:
                resources_new = set()
                for parent, child in (
                        session.query(res_anc, res_childs)
                        .filter(res_childs.type_name.in_(resources_set))
                        .filter(res_childs.parent_type_name ==
                                res_anc.type_name)
                        .all()):

                    if parent.type_name not in resources_set:
                        resources_new.add(parent.type_name)

                    resources_set.add(parent.type_name)
                    resources_set.add(child.type_name)

                    resource_graph[parent.type_name].add(child.type_name)

            return resource_graph

        @classmethod
        def find_resource_path(cls, session, resource_type_name):
            """Find resource ancestors by type/name format."""

            qry = (
                session.query(Resource)
                .filter(Resource.type_name == resource_type_name))

            resources = qry.all()
            return cls._find_resource_path(session, resources)

        @classmethod
        def _find_resource_path(cls, _, resources):
            """Find the list of transitive ancestors for the given resource."""

            if not resources:
                return []

            path = []
            resource = resources[0]

            path.append(resource)
            while resource.parent:
                resource = resource.parent
                path.append(resource)

            return path

        @classmethod
        def get_roles_by_permission_names(cls, session, permission_names):
            """Return the list of roles covering the specified permissions."""

            permission_set = set(permission_names)
            qry = session.query(Permission)
            if permission_set:
                qry = qry.filter(Permission.name.in_(permission_set))
            permissions = qry.all()

            roles = set()
            for permission in permissions:
                for role in permission.roles:
                    roles.add(role)

            result_set = set()
            for role in roles:
                role_permissions = set(
                    [p.name for p in role.permissions])
                if permission_set.issubset(role_permissions):
                    result_set.add(role)

            return result_set

        @classmethod
        def get_member(cls, session, name):
            """Get member by name."""

            return session.query(Member).filter(Member.name == name).all()

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
