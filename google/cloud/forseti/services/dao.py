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

# pylint: disable=too-many-lines
# pylint: disable=too-many-branches

import binascii
import collections
import hmac
import json
import os
import struct
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
from sqlalchemy.orm import aliased
from sqlalchemy.orm import joinedload
from sqlalchemy.orm import reconstructor
from sqlalchemy.orm import relationship
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm.exc import NoResultFound
from sqlalchemy.sql import select
from sqlalchemy.sql import union
from sqlalchemy.ext.declarative import declarative_base

from google.cloud.forseti.common.util import date_time
from google.cloud.forseti.services.utils import mutual_exclusive
from google.cloud.forseti.services.utils import to_full_resource_name
from google.cloud.forseti.services import db
from google.cloud.forseti.services.utils import get_sql_dialect
from google.cloud.forseti.common.util import logger


LOGGER = logger.get_logger(__name__)

POOL_RECYCLE_SECONDS = 300
PER_YIELD = 1024


def generate_model_handle():
    """Generate random model handle.

    Returns:
        str: random bytes for handle
    """

    return binascii.hexlify(os.urandom(16))


def generate_model_seed():
    """Generate random model seed.

    Returns:
        str: random bytes
    """

    return binascii.hexlify(os.urandom(16))


MODEL_BASE = declarative_base()


class Model(MODEL_BASE):
    """Explain model object in database."""

    __tablename__ = 'model'
    name = Column(String(32), primary_key=True)
    handle = Column(String(32))
    state = Column(String(32))
    description = Column(Text())
    watchdog_timer_datetime = Column(DateTime())
    created_at_datetime = Column(DateTime())
    etag_seed = Column(String(32), nullable=False)
    message = Column(Text(16777215))
    warnings = Column(Text(16777215))

    def __init__(self, *args, **kwargs):
        """Initialize

        Args:
            *args (list): Arguments.
            **kwargs (dict): Arguments.
        """
        super(Model, self).__init__(*args, **kwargs)
        # Non-SQL attributes
        self.warning_store = list()

    @reconstructor
    def init_on_load(self):
        """Initialization of model when reconstructed from query."""
        self.warning_store = list()

    def kick_watchdog(self):
        """Used during import to notify the import is still progressing."""

        self.watchdog_timer_datetime = date_time.get_utc_now_datetime()

    def add_warning(self, warning):
        """Add a warning to the model.

        Args:
            warning (str): Warning message
        """
        if warning:
            self.warning_store.append(warning)

    def get_warnings(self):
        """Returns any stored warnings.

        Returns:
            str: warning message
        """
        if self.warning_store:
            return '\n'.join(self.warning_store)
        return ''

    def set_inprogress(self):
        """Set state to 'in progress'."""

        self.state = 'INPROGRESS'

    def add_description(self, description):
        """Add new description to the model

        Args:
            description (str): the description to be added in json format
        """

        new_desc = json.loads(description)
        model_desc = json.loads(self.description)

        for new_item in new_desc:
            model_desc[new_item] = new_desc[new_item]

        self.description = json.dumps(model_desc, sort_keys=True)

    def set_done(self, message=''):
        """Indicate a finished import.

        Args:
            message (str): Success message or ''
        """
        warnings = self.get_warnings()
        if warnings:
            LOGGER.debug('warnings = %s', warnings)
            self.warnings = warnings
            self.state = 'PARTIAL_SUCCESS'
        else:
            self.state = 'SUCCESS'
        self.message = message

    def set_error(self, message):
        """Indicate a broken import.

        Args:
            message (str): error message
        """

        self.state = 'BROKEN'
        self.warnings = self.get_warnings()
        self.message = message
        LOGGER.error('warning = %s, message = %s',
                     self.warnings, self.message)

    def __repr__(self):
        """String representation.

        Returns:
            str: Model represented as
                (name='{}', handle='{}' state='{}')
        """

        return '<Model(name={}, handle={} state={})>'.format(
            self.name, self.handle, self.state)


# pylint: disable=too-many-locals,no-member
def define_model(model_name, dbengine, model_seed):
    """Defines table classes which point to the corresponding model.

        This means, for each model being accessed this function needs to
        be called in order to generate a full set of table definitions.

        Models are name spaced via a random model seed such that multiple
        models can exist within the same database. In order to implement
        the name spacing in an abstract way.

    Args:
        model_name (str): model handle
        dbengine (object): db engine
        model_seed (str): seed to get etag

    Returns:
        tuple: (sessionmaker, ModelAccess)
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

    group_members = Table(
        '{}_group_members'.format(model_name),
        base.metadata,
        Column('group_name',
               ForeignKey('{}.name'.format(members_tablename)),
               primary_key=True),
        Column('members_name',
               ForeignKey('{}.name'.format(members_tablename)),
               primary_key=True),
    )

    def get_string_by_dialect(db_dialect, column_size):
        """Get Sqlalchemy String by dialect.
        Sqlite doesn't support collation type, need to define different
        column types for different database engine.

        This is used to make MySQL column case sensitive by adding
        an encoding type.
        Args:
            db_dialect (String): The db dialect.
            column_size (Integer): The size of the column.

        Returns:
            String: Sqlalchemy String.
        """
        if db_dialect.lower() == 'sqlite':
            return String(column_size)
        return String(column_size, collation='utf8mb4_bin')

    class Resource(base):
        """Row entry for a GCP resource."""
        __tablename__ = resources_tablename

        full_name = Column(String(2048), nullable=False)
        type_name = Column(get_string_by_dialect(dbengine.dialect.name, 512),
                           primary_key=True)
        parent_type_name = Column(
            get_string_by_dialect(dbengine.dialect.name, 512),
            ForeignKey('{}.type_name'.format(resources_tablename)))
        name = Column(String(256), nullable=False)
        type = Column(String(128), nullable=False)
        policy_update_counter = Column(Integer, default=0)
        display_name = Column(String(256), default='')
        email = Column(String(256), default='')
        data = Column(Text(16777215))

        parent = relationship('Resource', remote_side=[type_name])
        bindings = relationship('Binding', back_populates='resource')

        def increment_update_counter(self):
            """Increments counter for this object's db updates.
            """
            self.policy_update_counter += 1

        def get_etag(self):
            """Return the etag for this resource.

            Returns:
                str: etag to avoid race condition when set policy
            """
            serialized_ctr = struct.pack('>I', self.policy_update_counter)
            msg = binascii.hexlify(serialized_ctr)
            msg += self.full_name
            return hmac.new(model_seed.encode('utf-8'), msg).hexdigest()

        def __repr__(self):
            """String representation.

            Returns:
                str: Resource represented as
                    (full_name='{}', name='{}' type='{}')
            """
            return '<Resource(full_name={}, name={} type={})>'.format(
                self.full_name, self.name, self.type)

    Resource.children = relationship(
        'Resource', order_by=Resource.full_name, back_populates='parent')

    class Binding(base):
        """Row for a binding between resource, roles and members."""

        __tablename__ = bindings_tablename
        id = Column(Integer, Sequence('{}_id_seq'.format(bindings_tablename)),
                    primary_key=True)
        resource_type_name = Column(
            get_string_by_dialect(dbengine.dialect.name, 512),
            ForeignKey('{}.type_name'.format(resources_tablename)))

        role_name = Column(String(128), ForeignKey(
            '{}.name'.format(roles_tablename)))

        resource = relationship('Resource', remote_side=[resource_type_name])
        role = relationship('Role', remote_side=[role_name])

        members = relationship('Member',
                               secondary=binding_members,
                               back_populates='bindings')

        def __repr__(self):
            """String Representation

            Returns:
                str: Binding represented as
                    (id='{}', role='{}', resource='{}' members='{}')
            """
            fmt_s = '<Binding(id={}, role={}, resource={} members={})>'
            return fmt_s.format(
                self.id,
                self.role_name,
                self.resource_type_name,
                self.members)

    class Member(base):
        """Row entry for a policy member."""

        __tablename__ = members_tablename
        name = Column(String(256), primary_key=True)
        type = Column(String(64))
        member_name = Column(String(256))

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
            """String representation.

            Returns:
                str: Member represented as (name='{}', type='{}')
            """
            return '<Member(name={}, type={})>'.format(
                self.name, self.type)

    class GroupInGroup(base):
        """Row for a group-in-group membership."""

        __tablename__ = denormed_group_in_group
        parent = Column(String(256), primary_key=True)
        member = Column(String(256), primary_key=True)

        def __repr__(self):
            """String representation.

            Returns:
                str: GroupInGroup represented as (parent='{}', member='{}')
            """
            return '<GroupInGroup(parent={}, member={})>'.format(
                self.parent,
                self.member)

    class Role(base):
        """Row entry for an IAM role."""

        __tablename__ = roles_tablename
        name = Column(String(128), primary_key=True)
        title = Column(String(128), default='')
        stage = Column(String(128), default='')
        description = Column(String(1024), default='')
        custom = Column(Boolean, default=False)
        permissions = relationship('Permission',
                                   secondary=role_permissions,
                                   back_populates='roles')

        def __repr__(self):
            """String Representation

            Returns:
                str: Role represented by name
            """
            return '<Role(name=%s)>' % self.name

    class Permission(base):
        """Row entry for an IAM permission."""

        __tablename__ = permissions_tablename
        name = Column(String(128), primary_key=True)
        roles = relationship('Role',
                             secondary=role_permissions,
                             back_populates='permissions')

        def __repr__(self):
            """String Representation

            Returns:
                str: Permission represented by name
            """
            return '<Permission(name=%s)>' % self.name

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

        # Set of member binding types that expand like groups.
        GROUP_TYPES = {'group',
                       'projecteditor',
                       'projectowner',
                       'projectviewer'}

        # Members that represent all users
        ALL_USER_MEMBERS = ['allusers', 'allauthenticatedusers']

        @classmethod
        def delete_all(cls, engine):
            """Delete all data from the model.

            Args:
                engine (object): database engine
            """

            LOGGER.info('Deleting all data from the model.')
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

            This method will fill the GroupInGroup table with
            (parent, member) if parent is an ancestor of member,
            whenever adding or removing a new group or group-group
            relationship, this method should be called to re-denormalize

            Args:
                session (object): Database session to use.

            Returns:
                int: Number of iterations.

            Raises:
                Exception: dernomalize fail
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
                qry = (GroupInGroup.__table__.insert().from_select(
                    ['parent', 'member'], group_members.select().where(
                        group_members.c.group_name.startswith('group/')
                    ).where(
                        group_members.c.members_name.startswith('group/')
                    )
                ))

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
                        select([tbl1.c.parent,
                                tbl2.c.member])
                        .select_from(expansion)
                        # pylint: disable=singleton-comparison
                        .where(tbl3.c.parent == None)
                        .distinct()
                    )

                    # Execute the query and insert into the table
                    qry = (GroupInGroup.__table__
                           .insert()
                           .from_select(['parent', 'member'], stmt))

                    rows_affected = bool(session.execute(qry).rowcount)
                    iterations += 1
            except Exception as e:
                LOGGER.exception(e)
                session.rollback()
                raise
            finally:
                if get_sql_dialect(session) != 'sqlite':
                    session.execute('UNLOCK TABLES')
                session.commit()
            return iterations

        @classmethod
        def expand_special_members(cls, session):
            """Create dynamic groups for project(Editor|Owner|Viewer).

            Should be called after IAM bindings are added to the model.

            Args:
                session (object): Database session to use.
            """
            member_type_map = {
                'projecteditor': 'roles/editor',
                'projectowner': 'roles/owner',
                'projectviewer': 'roles/viewer'}
            for parent_member in cls.list_group_members(
                    session, '', member_types=member_type_map.keys()):
                member_type, project_id = parent_member.split('/')
                role = member_type_map[member_type]
                try:
                    iam_policy = cls.get_iam_policy(
                        session,
                        'project/{}'.format(project_id),
                        roles=[role])
                    LOGGER.info('iam_policy: %s', iam_policy)
                except NoResultFound:
                    LOGGER.warning('Found a non-existent project, or project '
                                   'outside of the organization, in an IAM '
                                   'binding: %s', parent_member)
                    continue
                members = iam_policy.get('bindings', {}).get(role, [])
                expanded_members = cls.expand_members(session, members)
                for member in expanded_members:
                    stmt = cls.TBL_MEMBERSHIP.insert(
                        {'group_name': parent_member,
                         'members_name': member.name})
                    session.execute(stmt)
                    if member.type == 'group' and member.name in members:
                        session.add(cls.TBL_GROUP_IN_GROUP(
                            parent=parent_member,
                            member=member.name))
            session.commit()

        @classmethod
        def explain_granted(cls, session, member_name, resource_type_name,
                            role, permission):
            """Provide info about how the member has access to the resource.

            For example, member m1 can access resource r1 with permission p
            it might be granted by binding (r2, rol, g1),
            r1 is a child resource in a project or folder r2,
            role rol contains permission p,
            m1 is a member in group g1.
            This method list bindings that grant the access, member relation
            and resource hierarchy

            Args:
                session (object): Database session.
                member_name (str): name of the member
                resource_type_name (str): type_name of the resource
                role (str): role to query
                permission (str): permission to query

            Returns:
                tuples: (bindings, member_graph, resource_type_names) bindings,
                    the bindings to grant the access member_graph, the graph to
                    have member included in the binding esource_type_names, the
                    resource tree

            Raises:
                Exception: not granted
            """
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
                error_message = 'Grant not found: ({},{},{})'.format(
                    member_name,
                    resource_type_name,
                    role if role is not None else permission)
                LOGGER.error(error_message)
                raise Exception(error_message)
            else:
                bindings = [(b.resource_type_name, b.role_name, m.name)
                            for b, m in result]
                return bindings, member_graph, resource_type_names

        @classmethod
        def scanner_iter(cls, session, resource_type,
                         parent_type_name=None):
            """Iterate over all resources with the specified type.

            Args:
                session (object): Database session.
                resource_type (str): type of the resource to scan
                parent_type_name (str): type_name of the parent resource

            Yields:
                Resource: resource that match the query
            """

            qry = (
                session.query(Resource)
                .filter(Resource.type == resource_type)
                .options(joinedload(Resource.parent))
                .enable_eagerloads(True))

            if parent_type_name:
                qry = qry.filter(Resource.parent_type_name == parent_type_name)

            for resource in qry.yield_per(PER_YIELD):
                yield resource

        @classmethod
        def explain_denied(cls, session, member_name, resource_type_names,
                           permission_names, role_names):
            """Explain why an access is denied

            Provide information how to grant access to a member if such
            access is denied with current IAM policies.
            For example, member m1 cannot access resource r1 with permission
            p, this method shows the bindings with rol that covered the
            desired permission on the resource r1 and its ancestors.
            If adding this member to any of these bindings, such access
            can be granted. An overgranting level is also provided

            Args:
                session (object): Database session.
                member_name (str): name of the member
                resource_type_names (list): list of type_names of resources
                permission_names (list): list of permissions
                role_names (list): list of roles

            Returns:
                list: list of tuples,
                    (overgranting,[(role_name,member_name,resource_name)])

            Raises:
                Exception: No roles covering requested permission set,
                    Not possible
            """

            if not role_names:
                role_names = [r.name for r in
                              cls.get_roles_by_permission_names(
                                  session,
                                  permission_names)]
                if not role_names:
                    error_message = 'No roles covering requested permission set'
                    LOGGER.error(error_message)
                    raise Exception(error_message)

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

                Args:
                    resource_hierarchy (dict): graph of the resource hierarchy

                Returns:
                    list: candidates to add to bindings that potentially grant
                        access
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
                .join(binding_members)
                .join(Member)
                .join(Role)
                .filter(Binding.resource_type_name.in_(
                    bind_res_candidates))
                .filter(Role.name.in_(role_names))
                .filter(or_(Member.type == 'group',
                            Member.name == member_name))
                .filter(and_((binding_members.c.bindings_id ==
                              Binding.id),
                             (binding_members.c.members_name ==
                              Member.name)))
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
            """Return the set of resources the member has access to.

            By default, this method expand group_member relation,
            so the result includes all resources can be accessed by the
            groups that the member is in.
            By default, this method does not expand resource hierarchy,
            so the result does not include a resource if such resource does
            not have a direct binding to allow access.

            Args:
                session (object): Database session.
                member_name (str): name of the member
                permission_names (list): list of names of permissions to query
                expand_resources (bool): whether to expand resources
                reverse_expand_members (bool): whether to expand members

            Returns:
                list: list of access tuples, ("role_name", "resource_type_name")
            """

            if reverse_expand_members:
                member_names = [m.name for m in
                                cls.reverse_expand_members(session,
                                                           [member_name],
                                                           False)]
            else:
                member_names = [member_name]

            roles = cls.get_roles_by_permission_names(
                session, permission_names)

            qry = (
                session.query(Binding)
                .join(binding_members)
                .join(Member)
                .filter(Binding.role_name.in_([r.name for r in roles]))
                .filter(Member.name.in_(member_names))
            )

            bindings = qry.yield_per(1024)
            if not expand_resources:
                return [(binding.role_name,
                         [binding.resource_type_name]) for binding in bindings]

            r_type_names = [binding.resource_type_name for binding in bindings]
            expansion = cls.expand_resources_by_type_names(
                session,
                r_type_names)

            res_exp = {k.type_name: [v.type_name for v in values]
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
            """Query access via the specified permission

            Return all the (Principal, Resource) combinations allowing
            satisfying access via the specified permission.
            By default, the group relation and resource hierarchy will not be
            expanded, so the results will only contains direct bindings
            filtered by permission. But the relations can be expanded

            Args:
                session (object): Database session.
                role_name (str): Role name to query for
                permission_name (str): Permission name to query for.
                expand_groups (bool): Whether or not to expand groups.
                expand_resources (bool): Whether or not to expand resources.

            Yields:
                obejct: A generator of access tuples.

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
                error_message = 'Either role or permission must be set'
                LOGGER.error(error_message)
                raise ValueError(error_message)

            if expand_resources:
                expanded_resources = aliased(Resource)
                qry = (
                    session.query(expanded_resources, Binding, Member)
                    .filter(binding_members.c.bindings_id == Binding.id)
                    .filter(binding_members.c.members_name == Member.name)
                    .filter(expanded_resources.full_name.startswith(
                        Resource.full_name))
                    .filter((Resource.type_name ==
                             Binding.resource_type_name))
                    .filter(Binding.role_name.in_(role_names))
                    .order_by(expanded_resources.name.asc(),
                              Binding.role_name.asc())
                )
            else:
                qry = (
                    session.query(Resource, Binding, Member)
                    .filter(binding_members.c.bindings_id == Binding.id)
                    .filter(binding_members.c.members_name == Member.name)
                    .filter((Resource.type_name ==
                             Binding.resource_type_name))
                    .filter(Binding.role_name.in_(role_names))
                    .order_by(Resource.name.asc(), Binding.role_name.asc())
                )

            if expand_groups:
                to_expand = set([m.name for _, _, m in
                                 qry.yield_per(PER_YIELD)])
                expansion = cls.expand_members_map(session, to_expand,
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
            """Query access by resource

            Return members who have access to the given resource.
            The resource hierarchy will always be expanded, so even if the
            current resource does not have that binding, if its ancestors
            have the binding, the access will be shown
            By default, the group relationship will not be expanded

            Args:
                session (object): db session
                resource_type_name (str): type_name of the resource to query
                permission_names (list): list of strs, names of the permissions
                    to query
                expand_groups (bool): whether to expand groups

            Returns:
                dict: role_member_mapping, <"role_name", "member_names">
            """

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
            """Resolve permissions for the role.

            Args:
                session (object): db session
                role_names (list): list of strs, names of the roles
                role_prefixes (list): list of strs, prefixes of the roles
                _ (int): place occupation

            Returns:
                list: list of (Role, Permission)

            Raises:
                Exception: No roles or role prefixes specified
            """

            if not role_names and not role_prefixes:
                error_message = 'No roles or role prefixes specified'
                LOGGER.error(error_message)
                raise Exception(error_message)
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
        def set_iam_policy(cls,
                           session,
                           resource_type_name,
                           policy,
                           update_members=False):
            """Set IAM policy

            Sets an IAM policy for the resource, check the etag when setting
            new policy and reassign new etag.
            Check etag to avoid race condition

            Args:
                session (object): db session
                resource_type_name (str): type_name of the resource
                policy (dict): the policy to set on the resource
                update_members (bool): If true, then add new members to Member
                    table. This must be set when the call to set_iam_policy
                    happens outside of the model InventoryImporter class. Tests
                    or users that manually add an IAM policy need to mark this
                    as true to ensure the model remains consistent.

            Raises:
                Exception: Etag doesn't match
            """

            LOGGER.info('Setting IAM policy, resource_type_name = %s, policy'
                        ' = %s, session = %s',
                        resource_type_name, policy, session)
            old_policy = cls.get_iam_policy(session, resource_type_name)
            if policy['etag'] != old_policy['etag']:
                error_message = 'Etags distinct, stored={}, provided={}'.format(
                    old_policy['etag'], policy['etag'])
                LOGGER.error(error_message)
                raise Exception(error_message)

            old_policy = old_policy['bindings']
            policy = policy['bindings']

            def filter_etag(policy):
                """Filter etag key/value out of policy map.

                Args:
                    policy (dict): the policy to filter

                Returns:
                    dict: policy without etag, <"bindings":[<role, members>]>

                Raises:
                """

                return {k: v for k, v in policy.iteritems() if k != 'etag'}

            def calculate_diff(policy, old_policy):
                """Calculate the grant/revoke difference between policies.
                   The diff = policy['bindings'] - old_policy['bindings']

                Args:
                    policy (dict): the new policy in dict format
                    old_policy (dict): the old policy in dict format

                Returns:
                    dict: <role, members> diff of bindings
                """

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
                    .filter((Binding.resource_type_name ==
                             resource_type_name))
                    .filter(Binding.role_name == role)
                    .join(binding_members).join(Member)
                    .filter(Member.name.in_(members)).all())

                for binding in bindings:
                    session.delete(binding)

            for role, members in grants.iteritems():
                inserted = False
                existing_bindings = (
                    session.query(Binding)
                    .filter((Binding.resource_type_name ==
                             resource_type_name))
                    .filter(Binding.role_name == role)
                    .all())

                if update_members:
                    for member in members:
                        if not cls.get_member(session, member):
                            try:
                                # This is the default case, e.g. 'group/foobar'
                                m_type, name = member.split('/', 1)
                            except ValueError:
                                # Special groups like 'allUsers'
                                m_type, name = member, member
                            session.add(cls.TBL_MEMBER(
                                name=member,
                                type=m_type,
                                member_name=name))

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
        def get_iam_policy(cls, session, resource_type_name, roles=None):
            """Return the IAM policy for a resource.

            Args:
                session (object): db session
                resource_type_name (str): type_name of the resource to query
                roles (list): An optional list of roles to limit the results to

            Returns:
                dict: the IAM policy
            """

            resource = session.query(Resource).filter(
                Resource.type_name == resource_type_name).one()
            policy = {'etag': resource.get_etag(),
                      'bindings': {},
                      'resource': resource.type_name}
            bindings = session.query(Binding).filter(
                Binding.resource_type_name == resource_type_name)
            if roles:
                bindings = bindings.filter(Binding.role_name.in_(roles))
            for binding in bindings.all():
                role = binding.role_name
                members = [m.name for m in binding.members]
                policy['bindings'][role] = members
            return policy

        @classmethod
        def check_iam_policy(cls, session, resource_type_name, permission_name,
                             member_name):
            """Check access according to the resource IAM policy.

            Args:
                session (object): db session
                resource_type_name (str): type_name of the resource to check
                permission_name (str): name of the permission to check
                member_name (str): name of the member to check

            Returns:
                bool: whether such access is allowed

            Raises:
                Exception: member or resource not found
            """

            member_names = [m.name for m in
                            cls.reverse_expand_members(
                                session,
                                [member_name])]
            resource_type_names = [r.type_name for r in cls.find_resource_path(
                session,
                resource_type_name)]

            if not member_names:
                error_message = 'Member not found: {}'.format(member_name)
                LOGGER.error(error_message)
                raise Exception(error_message)
            if not resource_type_names:
                error_message = 'Resource not found: {}'.format(
                    resource_type_name)
                LOGGER.error(error_message)
                raise Exception(error_message)

            return (session.query(Permission)
                    .filter(Permission.name == permission_name)
                    .join(role_permissions).join(Role).join(Binding)
                    .filter(Binding.resource_type_name.in_(resource_type_names))
                    .join(binding_members).join(Member)
                    .filter(Member.name.in_(member_names)).first() is not None)

        @classmethod
        def list_roles_by_prefix(cls, session, role_prefix):
            """Provides a list of roles matched via name prefix.

            Args:
                session (object): db session
                role_prefix (str): prefix of the role_name

            Returns:
                list: list of role_names that match the query
            """

            return [r.name for r in session.query(Role).filter(
                Role.name.startswith(role_prefix)).all()]

        @classmethod
        def add_role_by_name(cls, session, role_name, permission_names):
            """Creates a new role.

            Args:
                session (object): db session
                role_name (str): name of the role to add
                permission_names (list): list of permissions in the role
            """

            LOGGER.info('Creating a new role, role_name = %s, permission_names'
                        ' = %s, session = %s',
                        role_name, permission_names, session)
            permission_names = set(permission_names)
            existing_permissions = session.query(Permission).filter(
                Permission.name.in_(permission_names)).all()
            for existing_permission in existing_permissions:
                try:
                    permission_names.remove(existing_permission.name)
                except KeyError:
                    LOGGER.warn('existing_permissions.name = %s, KeyError',
                                existing_permission.name)

            new_permissions = [Permission(name=n) for n in permission_names]
            for perm in new_permissions:
                session.add(perm)
            cls.add_role(session, role_name,
                         existing_permissions + new_permissions)
            session.commit()

        @classmethod
        def add_group_member(cls,
                             session,
                             member_type_name,
                             parent_type_names,
                             denorm=False):
            """Add member, optionally with parent relationship.

            Args:
                session (object): db session
                member_type_name (str): type_name of the member to add
                parent_type_names (list): type_names of the parents
                denorm (bool): whether to denorm the groupingroup table after
                    addition
            """

            LOGGER.info('Adding a member, member_type_name = %s,'
                        ' parent_type_names = %s, denorm = %s, session = %s',
                        member_type_name, parent_type_names, denorm, session)

            cls.add_member(session,
                           member_type_name,
                           parent_type_names,
                           denorm)
            session.commit()

        @classmethod
        def list_group_members(cls,
                               session,
                               member_name_prefix,
                               member_types=None):
            """Returns members filtered by prefix.

            Args:
                session (object): db session
                member_name_prefix (str): the prefix of the member_name
                member_types (list): an optional list of member types to filter
                    the results by.

            Returns:
                list: list of Members that match the query
            """

            qry = session.query(Member).filter(
                Member.member_name.startswith(member_name_prefix))
            if member_types:
                qry = qry.filter(Member.type.in_(member_types))
            return [m.name for m in qry.all()]

        @classmethod
        def iter_groups(cls, session):
            """Returns iterator of all groups in model.

            Args:
                session (object): db session

            Yields:
                Member: group in the model
            """

            qry = session.query(Member).filter(Member.type == 'group')
            for group in qry.yield_per(1024):
                yield group

        @classmethod
        def iter_resources_by_prefix(cls,
                                     session,
                                     full_resource_name_prefix=None,
                                     type_name_prefix=None,
                                     type_prefix=None,
                                     name_prefix=None):
            """Returns iterator to resources filtered by prefix.

            Args:
                session (object): db session
                full_resource_name_prefix (str): the prefix of the
                    full_resource_name
                type_name_prefix (str): the prefix of the type_name
                type_prefix (str): the prefix of the type
                name_prefix (ste): the prefix of the name

            Yields:
                Resource: that match the query

            Raises:
                Exception: No prefix given
            """

            if not any([arg is not None for arg in [full_resource_name_prefix,
                                                    type_name_prefix,
                                                    type_prefix,
                                                    name_prefix]]):
                error_message = 'At least one prefix must be set'
                LOGGER.error(error_message)
                raise Exception(error_message)

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
            """Returns resources filtered by prefix.

            Args:
                session (object): db session
                full_resource_name_prefix (str): the prefix of the
                    full_resource_name
                type_name_prefix (str): the prefix of the type_name
                type_prefix (str): the prefix of the type
                name_prefix (ste): the prefix of the name

            Returns:
                list: list of Resources match the query

            Raises:
            """

            return list(
                cls.iter_resources_by_prefix(session,
                                             full_resource_name_prefix,
                                             type_name_prefix,
                                             type_prefix,
                                             name_prefix))

        @classmethod
        def add_resource_by_name(cls,
                                 session,
                                 resource_type_name,
                                 parent_type_name,
                                 no_require_parent):
            """Adds resource specified via full name.

            Args:
                session (object): db session
                resource_type_name (str): name of the resource
                parent_type_name (str): name of the parent resource
                no_require_parent (bool): if this resource has a parent

            Returns:
                Resource: Created new resource
            """

            LOGGER.info('Adding resource via full name, resource_type_name'
                        ' = %s, parent_type_name = %s, no_require_parent = %s,'
                        ' session = %s', resource_type_name,
                        parent_type_name, no_require_parent, session)
            if not no_require_parent:
                parent = session.query(Resource).filter(
                    Resource.type_name == parent_type_name).one()
            else:
                parent = None
            return cls.add_resource(session, resource_type_name, parent)

        @classmethod
        def add_resource(cls, session, resource_type_name, parent=None):
            """Adds resource by name.

            Args:
                session (object): db session
                resource_type_name (str): name of the resource
                parent (Resource): parent of the resource

            Returns:
                Resource: Created new resource
            """

            LOGGER.info('Adding resource by name, resource_type_name = %s,'
                        ' session = %s', resource_type_name, session)
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
            """Add role by name.

            Args:
                session (object): db session
                name (str): name of the role to add
                permissions (list): permissions to add in the role

            Returns:
                Role: The created role
            """

            LOGGER.info('Adding role, name = %s, permissions = %s,'
                        ' session = %s', name, permissions, session)
            permissions = [] if permissions is None else permissions
            role = Role(name=name, permissions=permissions)
            session.add(role)
            return role

        @classmethod
        def add_permission(cls, session, name, roles=None):
            """Add permission by name.

            Args:
                session (object): db session
                name (str): name of the permission
                roles (list): list od roles to add the permission

            Returns:
                Permission: The created permission
            """

            LOGGER.info('Adding permission, name = %s, roles = %s'
                        ' session = %s', name, roles, session)
            roles = [] if roles is None else roles
            permission = Permission(name=name, roles=roles)
            session.add(permission)
            return permission

        @classmethod
        def add_binding(cls, session, resource, role, members):
            """Add a binding to the model.

            Args:
                session (object): db session
                resource (str): Resource to be added in the binding
                role (str): Role to be added in the binding
                members (list): members to be added in the binding

            Returns:
                Binding: the created binding
            """

            LOGGER.info('Adding a binding to the model, resource = %s,'
                        ' role = %s, members = %s, session = %s',
                        resource, role, members, session)
            binding = Binding(resource=resource, role=role, members=members)
            session.add(binding)
            return binding

        @classmethod
        def add_member(cls,
                       session,
                       type_name,
                       parent_type_names=None,
                       denorm=False):
            """Add a member to the model.

            Args:
                session (object): db session
                type_name (str): type_name of the resource to add
                parent_type_names (list): list of parent names to add
                denorm (bool): whether to denormalize the GroupInGroup relation

            Returns:
                Member: the created member

            Raises:
                Exception: parent not found
            """

            LOGGER.info('Adding a member to the model, type_name = %s,'
                        ' parent_type_names = %s, denorm = %s, session = %s',
                        type_name, parent_type_names, denorm, session)
            if not parent_type_names:
                parent_type_names = []
            res_type, name = type_name.split('/', 1)
            parents = session.query(Member).filter(
                Member.name.in_(parent_type_names)).all()
            if len(parents) != len(parent_type_names):
                msg = 'Parents: {}, expected: {}'.format(
                    parents, parent_type_names)
                error_message = 'Parent not found, {}'.format(msg)
                LOGGER.error(error_message)
                raise Exception(error_message)

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

            Args:
                session (object): db session
                res_type_names (list): list of resources in type_names

            Returns:
                dict: mapping in the form:
                      {res_type_name: Expansion(res_type_name), ... }
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
                    res_key.full_name))
                .yield_per(1024)
            )

            mapping = collections.defaultdict(set)
            for k, value in res:
                mapping[k].add(value)
            return mapping

        @classmethod
        def reverse_expand_members(cls, session, member_names,
                                   request_graph=False):
            """Expand members to their groups.

            List all groups that contains these members. Also return
            the graph if requested.

            Args:
                session (object): db session
                member_names (list): list of members to expand
                request_graph (bool): wether the parent-child graph is provided

            Returns:
                object: set if graph not requested, set and graph if requested
            """
            member_names.extend(cls.ALL_USER_MEMBERS)
            members = session.query(Member).filter(
                Member.name.in_(member_names)).all()
            membership_graph = collections.defaultdict(set)
            member_set = set()
            new_member_set = set()

            def add_to_sets(members, child):
                """Adds the members & children to the sets.

                Args:
                    members (list): list of Members to be added
                    child (Member): child to be added
                """

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
                session (object): db session
                member_names (set): Member names to expand
                show_group_members (bool): Whether to include subgroups
                member_contain_self (bool): Whether to include a parent
                    as its own member
            Returns:
                dict: <Member, set(Children)>
            """

            def separate_groups(member_names):
                """Separate groups and other members in two lists.

                This is a helper function. groups are needed to query on
                group_in_group table

                Args:
                    member_names (list): list of members to be separated

                Returns:
                    tuples: two lists of strs containing groups and others
                """
                groups = []
                others = []
                for name in member_names:
                    member_type = name.split('/')[0]
                    if member_type in cls.GROUP_TYPES:
                        groups.append(name)
                    else:
                        others.append(name)
                return groups, others

            selectables = []
            group_names, other_names = separate_groups(member_names)

            t_ging = GroupInGroup.__table__
            t_members = group_members

            # This resolves groups to its transitive non-group members.
            transitive_membership = (
                select([t_ging.c.parent, t_members.c.members_name])
                .select_from(t_ging.join(t_members,
                                         (t_ging.c.member ==
                                          t_members.c.group_name)))
            ).where(t_ging.c.parent.in_(group_names))

            if not show_group_members:
                transitive_membership = transitive_membership.where(
                    not_(t_members.c.members_name.startswith('group/')))

            selectables.append(
                transitive_membership.alias('transitive_membership'))

            direct_membership = (
                select([t_members.c.group_name,
                        t_members.c.members_name])
                .where(t_members.c.group_name.in_(group_names))
            )

            if not show_group_members:
                direct_membership = direct_membership.where(
                    not_(t_members.c.members_name.startswith('group/')))

            selectables.append(
                direct_membership.alias('direct_membership'))

            if show_group_members:
                # Show groups as members of other groups
                group_in_groups = (
                    select([t_ging.c.parent,
                            t_ging.c.member]).where(
                                t_ging.c.parent.in_(group_names))
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
            """Expand group membership towards the members.

            Args:
                session (object): db session
                member_names (list): list of strs of member names

            Returns:
                set: expanded group members
            """

            members = session.query(Member).filter(
                Member.name.in_(member_names)).all()

            def is_group(member):
                """Returns true iff the member is a group.

                Args:
                    member (Member): member to check

                Returns:
                    bool: whether the member is a group
                """
                return member.type in cls.GROUP_TYPES

            group_set = set()
            non_group_set = set()
            new_group_set = set()

            def add_to_sets(members):
                """Adds new members to the sets.

                Args:
                    members (list): members to be added
                """
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
            """Resolve the transitive ancestors by type/name format.

            Given a group of resource and find out all their parents.
            Then this method group the pairs with parent. Used to determine
            resource candidates to grant access in explain denied.

            Args:
                session (object): db session
                resource_type_names (list): list of strs, resources to query

            Returns:
                dict: <parent, childs> graph of the resource hierarchy
            """

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
            """Find resource ancestors by type/name format.

            Find all ancestors of a resource and return them in order

            Args:
                session (object): db session
                resource_type_name (str): resource to query

            Returns:
                list: list of Resources, transitive ancestors for the given
                    resource
            """

            qry = (
                session.query(Resource).filter(
                    Resource.type_name == resource_type_name)
            )

            resources = qry.all()
            return cls._find_resource_path(session, resources)

        @classmethod
        def _find_resource_path(cls, _, resources):
            """Find the list of transitive ancestors for the given resource.

            Args:
                _ (object): position holder
                resources (list): list of the resources to query

            Returns:
                list: list of Resources, transitive ancestors for the given
                    resource
            """

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
            """Return the list of roles covering the specified permissions.

            Args:
                session (object): db session
                permission_names (list): permissions to be covered by.

            Returns:
                set: roles set that cover the permissions
            """

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
            """Get member by name.

            Args:
                session (object): db session
                name (str): the name the member to query

            Returns:
                list: Members from the query
            """

            return session.query(Member).filter(Member.name == name).all()

    base.metadata.create_all(dbengine)
    return sessionmaker(bind=dbengine), ModelAccess


def undefine_model(session_maker, data_access):
    """Deletes an entire model and the corresponding data in the database.

    Args:
        session_maker (func): session_maker function
        data_access (ModelAccess): data access layer
    """

    session = session_maker()
    data_access.delete_all(session)


LOCK = Lock()


class ModelManager(object):
    """The Central class to create,list,get and delete models.

        ModelManager is mostly used to do the lookup from model name to the
        session cache which is given in each client's request.
    """

    def __init__(self, dbengine):
        """Initialization

        Args:
            dbengine (object): Database engine
        """
        self.engine = dbengine
        self.modelmaker = self._create_model_session()
        self.sessionmakers = {}

    def _create_model_session(self):
        """Create a session to read from the models table.

        Returns:
            object: db session created
        """

        MODEL_BASE.metadata.create_all(self.engine)
        return db.ScopedSessionMaker(
            sessionmaker(
                bind=self.engine),
            auto_commit=True)

    @mutual_exclusive(LOCK)
    def create(self, name):
        """Create a new model entry in the database.

        Args:
            name (str): model name

        Returns:
            str: the handle of the model
        """

        LOGGER.info('Creating a new model entry in the database,'
                    ' name = %s', name)
        handle = generate_model_handle()
        with self.modelmaker() as session:
            utc_now = date_time.get_utc_now_datetime()
            model = Model(
                handle=handle,
                name=name,
                state='CREATED',
                created_at_datetime=utc_now,
                watchdog_timer_datetime=utc_now,
                etag_seed=generate_model_seed(),
                description='{}'
            )
            session.add(model)
            self.sessionmakers[model.handle] = define_model(
                model.handle, self.engine, model.etag_seed)
            return handle

    def get(self, model):
        """Get model data by handle.

        Args:
            model (str): model handle

        Returns:
            tuple: session and ModelAccess object
        """

        session_maker, data_access = self._get(model)
        return db.ScopedSession(session_maker()), data_access

    def get_readonly_session(self):
        """Get read-only session.

        Returns:
            Session: The read-only session."""
        return db.create_scoped_readonly_session(self.engine)

    def _get(self, handle):
        """Get model data by name internal.

        Args:
            handle (str): the model handle

        Returns:
            Model: the model in the session maker

        Raises:
            KeyError: model handle not available
        """

        if handle not in [m.handle for m in self.models()]:
            error_message = 'handle={}, available={}'.format(
                handle,
                [m.handle for m in self.models()]
            )
            LOGGER.error(error_message)
            raise KeyError(error_message)
        try:
            return self.sessionmakers[handle]
        except KeyError:
            LOGGER.debug('Sessionmakers doesn\'t contain handle = %s,'
                         ' creating a new handle.', handle)
            with self.modelmaker() as session:
                model = (
                    session.query(Model).filter(Model.handle == handle).one()
                )
                self.sessionmakers[model.handle] = define_model(
                    model.handle, self.engine, model.etag_seed)
                return self.sessionmakers[model.handle]

    @mutual_exclusive(LOCK)
    def delete(self, model_name):
        """Delete a model entry in the database by name.

        Args:
            model_name (str): the name of the model to be deleted
        """

        LOGGER.info('Deleting model by name, model_name = %s', model_name)
        _, data_access = self._get(model_name)
        if model_name in self.sessionmakers:
            del self.sessionmakers[model_name]
        with self.modelmaker() as session:
            session.query(Model).filter(Model.handle == model_name).delete()
        data_access.delete_all(self.engine)

    def _models(self, expunge=False):
        """Return the list of models from the database.

        Args:
            expunge (bool): Whether or not to detach the object from
                the session for use in another session.

        Returns:
            list: list of Models in the db
        """

        with self.modelmaker() as session:
            items = session.query(Model).all()
            if expunge:
                session.expunge_all()
            return items

    def models(self):
        """Expunging wrapper for _models.

        Returns:
            list: list of Models in the db
        """
        return self._models(expunge=True)

    def model(self, model_name, expunge=True, session=None):
        """Get model from database by name.

        Args:
            model_name (str): Model name or handle
            expunge (bool): Whether or not to detach the object from
                the session for use in another session.
            session (object): Database session.

        Returns:
            Model: the dbo of the queried model
        """

        def instantiate_model(session, model_name, expunge):
            """Creates a model object by querying the database.

            Args:
                session (object): Database session.
                model_name (str): Model name to instantiate.
                expunge (bool): Whether or not to detach the object from
                    the session for use in another session.

            Returns:
                Model: the dbo of the queried model
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

    def get_model(self, model, expunge=True, session=None):
        """Get model from database by name or handle.

        Args:
            model (str): Model name or handle
            expunge (bool): Whether or not to detach the object from
                the session for use in another session.
            session (object): Database session.

        Returns:
            Model: the dbo of the queried model
        """

        def query_model(session, model, expunge):
            """Get a model object by querying the database.

            Args:
                session (object): Database session.
                model (str): Model name or handle.
                expunge (bool): Whether or not to detach the object from
                    the session for use in another session.

            Returns:
                Model: the dbo of the queried model
            """

            item = session.query(Model).filter(or_(
                Model.handle == model,
                Model.name == model)).first()
            if expunge and item:
                session.expunge(item)
            return item

        if not session:
            with self.modelmaker() as scoped_session:
                return query_model(scoped_session, model, expunge)
        else:
            return query_model(session, model, expunge)

    def add_description(self, model_name, new_description, session=None):
        """Add description to a model.

        Args:
            model_name (str): Model name
            new_description (str): The description in json format.
            session (object): Database session.
        """

        if not session:
            with self.modelmaker() as scoped_session:
                model = scoped_session.query(Model).filter(
                    Model.handle == model_name).one()
        else:
            model = session.query(Model).filter(
                Model.handle == model_name).one()
        model.add_description(new_description)

    def get_description(self, model_name, session=None):
        """Get the description to a model.

        Args:
            model_name (str): Model name
            session (object): Database session.

        Returns:
            json: Dictionary of the model description.
        """
        if not session:
            with self.modelmaker() as scoped_session:
                model = scoped_session.query(Model).filter(
                    Model.handle == model_name).one()
                return json.loads(model.description)
        else:
            model = session.query(Model).filter(
                Model.handle == model_name).one()
            return json.loads(model.description)


def create_engine(*args, **kwargs):
    """Create engine wrapper to patch database options.

    Args:
        *args (list): Arguments.
        **kwargs (dict): Arguments.

    Returns:
        object: Engine.
    """

    sqlite_enforce_fks = 'sqlite_enforce_fks'
    forward_kwargs = {k: v for k, v in kwargs.iteritems()}
    is_sqlite = False
    for arg in args:
        if 'sqlite' in arg:
            is_sqlite = True

    if sqlite_enforce_fks in forward_kwargs:
        del forward_kwargs[sqlite_enforce_fks]

    if is_sqlite:
        engine = sqlalchemy_create_engine(*args, **forward_kwargs)
    else:
        engine = sqlalchemy_create_engine(*args,
                                          pool_size=50,
                                          **forward_kwargs)
    dialect = engine.dialect.name
    if dialect == 'sqlite':
        @event.listens_for(engine, 'connect')
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

        @event.listens_for(engine, 'begin')
        def do_begin(conn):
            """Hooking database transaction begin.

            Args:
                conn (object): Database connection.
            """
            # Fix for nested transaction problems
            conn.execute('BEGIN')

        # pylint: disable=protected-access
        engine.__explain_hooks = [do_connect, do_begin]
        # pylint: enable=protected-access

    return engine


def session_creator(model_name, filename=None, seed=None, echo=False):
    """Create a session maker for the model and db file.

    Args:
        model_name (str): the model name
        filename (str): the db file to load the sqlite database
        seed (str): the unique model handle
        echo (bool): whether to echo all the statements

    Returns:
        tuple: session_maker and the ModelAccess object
    """
    LOGGER.info('Creating session maker, model_name = %s, filename = %s',
                model_name, filename)
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
