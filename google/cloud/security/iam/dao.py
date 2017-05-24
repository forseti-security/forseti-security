# Copyright 2017 Google Inc.
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

# Disable too-many-lines check
# pylint: disable=C0302

import datetime
import os
import binascii
import collections
import struct
import hmac
from threading import Lock


from sqlalchemy import Column, Integer, String, Sequence, ForeignKey
from sqlalchemy import create_engine, Table, DateTime, or_, and_
from sqlalchemy.orm import relationship, aliased, sessionmaker
from sqlalchemy.ext.declarative import declarative_base

from google.cloud.security.iam.utils import mutual_exclusive,\
    full_to_type_name, resource_to_type_name


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

    handle = Column(String, primary_key=True)
    state = Column(String)
    watchdog_timer = Column(DateTime)
    created_at = Column(DateTime)
    etag_seed = Column(String(32), nullable=False)

    def kick_watchdog(self, session):
        """
        Kick watchdog during import in order
        to notify the import is still progressing.
        """
        self.watchdog_timer = datetime.datetime.utcnow()
        session.commit()

    def set_inprogress(self, session):
        """Set state to 'in progress'."""
        self.state = "INPROGRESS"
        session.commit()

    def set_done(self, session):
        """Indicate a finished import."""
        self.state = "DONE"
        session.commit()


# pylint: disable=R0914
# pylint: disable=R0903
# pylint: disable=R0904
# pylint: disable=E1101
def define_model(model_name, dbengine, model_seed):
    """
    Models are name spaced via a random model seed such that multiple
    models can exist within the same database. In order to implement
    the name spacing in an abstract way, this function defines table
    classes which point to the corresponding model.
    This means, for each model being accessed this function needs to
    be called in order to generate a full set of table definitions.
    """
    base = declarative_base()

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

        full_name = Column(String, primary_key=True)
        name = Column(String)
        type = Column(String)
        policy_update_counter = Column(Integer, default=0)

        parent_name = Column(
            String, ForeignKey('{}.full_name'.format(resources_tablename)))
        parent = relationship("Resource", remote_side=[full_name])
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
        "Resource", order_by=Resource.name, back_populates="parent")

    class Member(base):
        """Row entry for a policy member."""
        __tablename__ = members_tablename

        name = Column(String, primary_key=True)
        type = Column(String)
        member_name = Column(String)

        parents = relationship(
            'Member',
            secondary=group_members,
            primaryjoin=name == group_members.c.group_name,
            secondaryjoin=name == group_members.c.members_name)

        children = relationship(
            'Member',
            secondary=group_members,
            primaryjoin=name == group_members.c.members_name,
            secondaryjoin=name == group_members.c.group_name)

        bindings = relationship('Binding',
                                secondary=binding_members,
                                back_populates='members')

        def __repr__(self):
            """String representation."""
            return "<Member(name='{}', type='{}')>".format(
                self.name, self.type)

    class Binding(base):
        """Row for a binding between resource, roles and members."""
        __tablename__ = bindings_tablename

        id = Column(Integer, Sequence('{}_id_seq'.format(bindings_tablename)),
                    primary_key=True)

        resource_name = Column(Integer, ForeignKey(
            '{}.name'.format(resources_tablename)))
        role_name = Column(Integer, ForeignKey(
            '{}.name'.format(roles_tablename)))

        resource = relationship('Resource', remote_side=[resource_name])
        role = relationship('Role', remote_side=[role_name])

        members = relationship('Member',
                               secondary=binding_members,
                               back_populates='bindings')

        def __repr__(self):
            return "<Binding(id='{}', role='{}', resource='{}' members='{}')>"\
                .format(self.id, self.role_name,
                        self.resource_name, self.members)

    class Role(base):
        """Row entry for an IAM role."""
        __tablename__ = roles_tablename

        name = Column(String, primary_key=True)
        permissions = relationship('Permission',
                                   secondary=role_permissions,
                                   back_populates='roles')

        def __repr__(self):
            return "<Role(name='%s')>" % (self.name)

    class Permission(base):
        """Row entry for an IAM permission."""
        __tablename__ = permissions_tablename

        name = Column(String, primary_key=True)
        roles = relationship('Role',
                             secondary=role_permissions,
                             back_populates='permissions')

        def __repr__(self):
            return "<Permission(name='%s')>" % (self.name)

    # pylint: disable=R0904
    class ModelAccess(object):
        """Data model facade, implement main API against database."""
        TBL_BINDING = Binding
        TBL_MEMBER = Member
        TBL_PERMISSION = Permission
        TBL_ROLE = Role
        TBL_RESOURCE = Resource

        def __init__(self):
            super(ModelAccess, self).__init__()

        @classmethod
        def delete_all(cls, engine):
            """Delete all data from the model."""
            Binding.__table__.drop(engine)
            Member.__table__.drop(engine)
            Permission.__table__.drop(engine)
            Role.__table__.drop(engine)
            Resource.__table__.drop(engine)
            role_permissions.drop(engine)
            binding_members.drop(engine)
            group_members.drop(engine)

        @classmethod
        def explain_granted(cls, session, member_name, full_resource_name,
                            role, permission):
            """Provide info about how the member has access to the resource."""
            members, member_graph = cls.reverse_expand_members(
                session, [member_name], request_graph=True)
            member_names = [m.name for m in members]
            resource_names = [r.full_name for r in
                              cls.find_resource_path(session,
                                                     full_resource_name)]

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

            qry = qry.filter(Binding.role_name.in_(roles))\
                     .filter(Member.name.in_(member_names))\
                     .filter(Binding.resource_name.in_(resource_names))
            result = qry.all()
            if not result:
                raise Exception(
                    'Grant not found: ({},{},{})'.format(
                        member_name,
                        full_resource_name,
                        role if role is not None else permission))
            else:
                bindings = [(b.resource_name, b.role_name, m.name)
                            for b, m in result]
                return bindings, member_graph, resource_names

        @classmethod
        def explain_denied(cls, session, member_name, resource_names,
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

            resource_hierarchy = cls.resolve_resource_ancestors(
                session, resource_names)

            def find_binding_candidates(resource_hierarchy):
                """
                Find the root node in the ancestors.
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

            bindings = session.query(Binding, Member)\
                .join(binding_members).join(Member).join(Role)\
                .filter(Binding.resource_name.in_(bind_res_candidates))\
                .filter(Role.name.in_(role_names))\
                .filter(or_(Member.type == 'group',
                            Member.name == member_name))\
                .filter(and_(binding_members.c.bindings_id == Binding.id,
                             binding_members.c.members_name == Member.name))\
                .filter(Role.name == Binding.role_name)\
                .all()

            strategies = []
            for resource in bind_res_candidates:
                for role_name in role_names:
                    overgranting = len(bind_res_candidates) - \
                        bind_res_candidates.index(resource) - 1
                    strategies.append(
                        (overgranting, [
                            (role, member_name, resource)
                            for role in [role_name]]))
            if bindings:
                for binding, member in bindings:
                    overgranting = len(bind_res_candidates) - 1\
                        - bind_res_candidates.index(binding.resource_name)
                    strategies.append(
                        (overgranting, [
                            (binding.role_name,
                             member.name,
                             binding.resource_name)]))
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
            qry = session.query(Binding).join(binding_members).join(Member)
            qry = qry.filter(Binding.role_name.in_([r.name for r in roles]))
            qry = qry.filter(Member.name.in_(member_names))
            bindings = qry.all()

            if not expand_resources:
                return [(binding.role_name,
                         [binding.resource_name]) for binding in bindings]
            else:
                r_type_names = ['/'.join(binding.resource_name.split('/')[-2:])
                                for binding in bindings]
                expansion = cls.expand_resources_by_type_names(
                    session,
                    r_type_names)

                def fmt(first, second):
                    """Formatting helper."""
                    return '{}/{}'.format(first, second)
                res_exp = {fmt(k.type, k.name):
                           [fmt(v.type, v.name) for v in values]
                           for k, values in expansion.iteritems()}

                return [(binding.role_name,
                         res_exp[full_to_type_name(binding.resource_name)])
                        for binding in bindings]

        @classmethod
        def query_access_by_resource(cls, session, resource_name,
                                     permission_names, expand_groups=False):
            """Return members who have access to the given resource."""
            roles = cls.get_roles_by_permission_names(
                session, permission_names)
            resources = cls.find_resource_path(session, resource_name)

            res = session.query(Binding, Member)\
                .filter(
                    Binding.role_name.in_([r.name for r in roles]),
                    Binding.resource_name.in_([r.full_name for r in resources])
                ).join(binding_members).join(Member)

            role_member_mapping = collections.defaultdict(set)
            for binding, member in res:
                role_member_mapping[binding.role_name].add(member.name)

            if expand_groups:
                for role in role_member_mapping:
                    role_member_mapping[role] =\
                        [m.name for m in cls.expand_members(
                            session,
                            role_member_mapping[role])]

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
        def denormalize(cls, session, per_yield=1024):
            """Denormalize the model into access triples."""
            qry = session.query(Binding)\
                .join(binding_members)\
                .join(Member)

            members = set()
            for binding in qry.all():
                for member in binding.members:
                    members.add(member.name)

            expanded_members = cls.expand_members_map(session, members)
            role_permissions_map = collections.defaultdict(set)

            qry = session.query(Role, Permission)\
                .join(role_permissions)\
                .filter(Role.name == role_permissions.c.roles_name)\
                .filter(Permission.name == role_permissions.c.permissions_name)

            for role, permission in qry.all():
                role_permissions_map[role.name].add(permission.name)

            for binding, member in \
                    session.query(Binding, Member)\
                    .join(binding_members)\
                    .filter(binding_members.c.bindings_id == Binding.id)\
                    .filter(binding_members.c.members_name == Member.name)\
                    .yield_per(per_yield):

                resource_type_name = full_to_type_name(binding.resource_name)
                resource_mapping = cls.expand_resources_by_type_names(
                    session,
                    [resource_type_name])

                f = resource_to_type_name
                resource_mapping = {f(k): set([f(m) for m in v])
                                    for k, v in resource_mapping.iteritems()}

                for expanded_member in expanded_members[member.name]:
                    for permission in role_permissions_map[binding.role_name]:
                        for res in resource_mapping[resource_type_name]:
                            triple = (permission, res, expanded_member)
                            yield triple

        @classmethod
        def set_iam_policy(cls, session, full_resource_name, policy):
            """Sets an IAM policy for the resource."""
            old_policy = cls.get_iam_policy(session, full_resource_name)
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
                bindings = session.query(Binding)\
                    .filter(Binding.resource_name == full_resource_name)\
                    .filter(Binding.role_name == role)\
                    .join(binding_members).join(Member)\
                    .filter(Member.name.in_(members)).all()
                for binding in bindings:
                    session.delete(binding)
            for role, members in grants.iteritems():
                inserted = False
                existing_bindings = session.query(Binding)\
                    .filter(Binding.resource_name == full_resource_name)\
                    .filter(Binding.role_name == role).all()
                for binding in existing_bindings:
                    if binding.role_name == role:
                        inserted = True
                        for member in members:
                            binding.members.append(
                                session.query(Member).filter(
                                    Member.name == member).one())
                if not inserted:
                    binding = Binding(
                        resource_name=full_resource_name,
                        role=session.query(Role).filter(
                            Role.name == role).one())
                    binding.members = session.query(Member).filter(
                        Member.name.in_(members)).all()
                    session.add(binding)
            resource = session.query(Resource).filter(
                Resource.full_name == full_resource_name).one()
            resource.increment_update_counter()
            session.commit()

        @classmethod
        def get_iam_policy(cls, session, full_resource_name):
            """Return the IAM policy for a resource."""
            resource = session.query(Resource).filter(
                Resource.full_name == full_resource_name).one()
            policy = {
                'etag': resource.get_etag(),
                'bindings': {},
                'resource': resource.full_name}
            for binding in session.query(Binding).filter(
                    Binding.resource_name == full_resource_name).all():
                role = binding.role_name
                members = [m.name for m in binding.members]
                policy['bindings'][role] = members
            return policy

        @classmethod
        def check_iam_policy(cls, session, full_resource_name, permission_name,
                             member_name):
            """Check access according to the resource IAM policy."""
            member_names = [m.name for m in
                            cls.reverse_expand_members(
                                session,
                                [member_name])]
            resource_names = [r.full_name for r in cls.find_resource_path(
                session,
                full_resource_name)]
            return session.query(Permission)\
                .filter(Permission.name == permission_name)\
                .join(role_permissions).join(Role).join(Binding)\
                .filter(Binding.resource_name.in_(resource_names))\
                .join(binding_members).join(Member)\
                .filter(Member.name.in_(member_names)).first() is not None

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
            map(session.add, new_permissions)
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
        def add_group_member(cls, session, member_type_name,
                             parent_type_names):
            """Add member, optionally with parent relationship."""
            cls.add_member(session, member_type_name, parent_type_names)
            session.commit()

        @classmethod
        def del_group_member(cls, session, member_type_name, parent_type_name,
                             only_delete_relationship):
            """Delete member."""
            if only_delete_relationship:
                group_members_delete = group_members.delete(
                    and_(group_members.c.group_name == member_type_name,
                         group_members.c.members_name == parent_type_name))
                session.execute(group_members_delete)
            else:
                session.query(Member)\
                    .filter(Member.name == member_type_name)\
                    .delete()
                group_members_delete = group_members.delete(
                    group_members.c.group_name == member_type_name)
                session.execute(group_members_delete)
            session.commit()

        @classmethod
        def list_group_members(cls, session, member_name_prefix):
            """Returns members filtered by prefix."""
            return [m.name for m in session.query(Member).filter(
                Member.member_name.startswith(member_name_prefix)).all()]

        @classmethod
        def list_resources_by_prefix(cls, session, full_resource_name_prefix):
            """Returns resources filtered by prefix."""
            return [r.full_name for r in session.query(Resource).filter(
                Resource.name.startswith(full_resource_name_prefix))
                    .all()]

        @classmethod
        def del_resource_by_type_name(cls, session, resource_type_name):
            """Deletes a resource specified by type/name."""
            res_type, res_name = resource_type_name.split('/')
            resource = session.query(Resource).filter(
                and_(Resource.type == res_type,
                     Resource.name == res_name)).one()
            return cls.del_resource_by_name(session, resource.full_name)

        @classmethod
        def del_resource_by_name(cls, session, full_resource_name):
            """Deletes a resource specified via full name."""
            session.query(Binding).filter(
                Binding.resource_name.startswith(full_resource_name)).delete(
                    synchronize_session='fetch')
            session.query(Resource).filter(
                Resource.full_name.startswith(full_resource_name)).delete(
                    synchronize_session='fetch')
            session.commit()

        @classmethod
        def add_resource_by_name(cls, session, full_name, no_require_parent):
            """Adds resource specified via full name."""
            if not no_require_parent:
                full_parent_name = '/'.join(full_name.split("/")[:-2])
                parent = session.query(Resource).filter(
                    Resource.full_name == full_parent_name).one()
            else:
                parent = None
            return cls.add_resource(session, full_name, parent)

        @classmethod
        def add_resource(cls, session, name, parent=None):
            """Adds resource by name."""
            res_type, res_name = name.split('/')[-2:]
            resource = Resource(full_name=name, name=res_name,
                                type=res_type, parent=parent)
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
        def add_member(cls, session, type_name, parent_type_names=None):
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
            return member

        @classmethod
        def expand_resources_by_type_names(cls, session, res_type_names):
            """
            Expand resources by type/name format.

            Returns: {res_type_name: Expansion(res_type_name), ... }
            """
            res_key = aliased(Resource, name='res_key')
            res_values = aliased(Resource, name='res_values')

            expressions = []
            for res_type_name in res_type_names:
                res_type, res_name = res_type_name.split('/')
                expressions.append(and_(
                    res_key.name == res_name,
                    res_key.type == res_type))

            res = session.query(res_key, res_values)\
                .filter(or_(*expressions)).filter(
                    res_values.full_name.startswith(res_key.full_name)).all()
            mapping = collections.defaultdict(set)
            for k, value in res:
                mapping[k].add(value)
            return mapping

        @classmethod
        def expand_resources_by_names(cls, session, res_names):
            """Expand resources by type/name format."""
            expressions = []
            for res_type, res_name in [res.split('/') for res in res_names]:
                expressions.append(and_(Resource.name == res_name,
                                        Resource.type == res_type))

            objects = session.query(Resource).filter(or_(*expressions)).all()
            full_resource_names = [r.full_name for r in objects]
            return cls.expand_resources(session, full_resource_names)

        @classmethod
        def expand_resources(cls, session, full_resource_names):
            """Expand resources towards the bottom."""
            if not isinstance(full_resource_names, list) and\
               not isinstance(full_resource_names, set):
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

            while len(new_resource_set) > 0:
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
            while len(new_member_set) > 0:
                members_to_walk = new_member_set
                new_member_set = set()
                for member in members_to_walk:
                    add_to_sets(member.parents, member)

            if request_graph:
                return member_set, membership_graph
            else:
                return member_set

        @classmethod
        def expand_members_map(cls, session, member_names):
            """Expand group membership keyed by member."""
            members = session.query(Member).filter(
                Member.name.in_(member_names)).all()

            member_map = collections.defaultdict(set)
            for member in members:
                member_map[member.name] = set()

            def is_group(member):
                """Returns true iff the member is a group."""
                return member.type == 'group'

            all_member_set = set([m.name for m in members])
            new_member_set = set([m.name for m in members if is_group(m)])

            while new_member_set:
                to_query_set = new_member_set
                new_member_set = set()

                qry = session.query(group_members)\
                    .filter(group_members.c.members_name.in_(to_query_set))
                for member, parent in qry.all():

                    member_map[parent].add(member)

                    if member.startswith('group/') and\
                       member not in all_member_set:
                        new_member_set.add(member)

                    all_member_set.add(parent)
                    all_member_set.add(member)

            def denormalize_membership(parent_name, member_map,
                                       cur_member_set):
                """Parent->members map to Parent->transitive members."""
                cur_member_set.add(parent_name)
                if parent_name not in member_map:
                    return set()
                members_to_add = member_map[parent_name]\
                    .difference(cur_member_set)
                for member in members_to_add:
                    cur_member_set.add(member)
                    new_members = denormalize_membership(member,
                                                         member_map,
                                                         cur_member_set)
                    cur_member_set = cur_member_set.union(new_members)
                return cur_member_set

            result = {m: denormalize_membership(m, member_map, set())
                      for m in member_names}
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

            while len(new_group_set) > 0:
                groups_to_walk = new_group_set
                new_group_set = set()
                for group in groups_to_walk:
                    add_to_sets(group.children)

            return group_set.union(non_group_set)

        @classmethod
        def resource_ancestors_by_name(cls, session, res_names):
            """Resolve the transitive ancestors by type/name format."""
            expressions = []
            for res_type, res_name in [r.split('/') for r in res_names]:
                expressions.append(and_(Resource.name == res_name,
                                        Resource.type == res_type))
            resources = session.query(Resource).filter(
                or_(*expressions)).all()
            full_resource_names = [r.full_name for r in resources]
            return cls.resolve_resource_ancestors(session, full_resource_names)

        @classmethod
        def resolve_resource_ancestors(cls, session, full_resource_names):
            """Resolve the transitive ancestors for the given resources."""
            resources = session.query(Resource).filter(
                Resource.full_name.in_(full_resource_names)).all()

            resource_names = set([r.full_name for r in resources])
            resource_graph = collections.defaultdict(set)

            res_childs = aliased(Resource, name='res_childs')
            res_anc = aliased(Resource, name='resource_parent')

            resources_set = set(resource_names)
            resources_new = set(resource_names)

            for resource in resources_new:
                resource_graph[resource] = set()

            while resources_new:
                resources_new = set()
                for parent, child in \
                    session.query(res_anc, res_childs)\
                        .filter(res_childs.full_name.in_(resources_set))\
                        .filter(res_childs.parent_name == res_anc.full_name)\
                        .all():

                    if parent.full_name not in resources_set:
                        resources_new.add(parent.full_name)

                    resources_set.add(parent.full_name)
                    resources_set.add(child.full_name)

                    resource_graph[parent.full_name].add(child.full_name)

            return resource_graph

        @classmethod
        def find_resource_path_by_name(cls, session, resource_name):
            """Find resource ancestors by type/name format."""
            res_type, res_name = resource_name.split('/')
            resources = session.query(Resource).filter(
                and_(Resource.name == res_name,
                     Resource.type == res_type))
            return cls._find_resource_path(session, resources)

        @classmethod
        def find_resource_path(cls, session, full_resource_name):
            """Find resource ancestors by full name."""
            resources = session.query(Resource).filter(
                Resource.full_name == full_resource_name).all()
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


class ScopedSession(object):
    """A scoped session is automatically released."""
    def __init__(self, session, auto_commit=False):
        self.session = session
        self.auto_commit = auto_commit

    def __enter__(self):
        return self.session

    def __exit__(self, exc_type, value, traceback):
        try:
            if traceback is None and self.auto_commit:
                self.session.commit()
        finally:
            self.session.close()


class ScopedSessionMaker(object):
    """Wraps session maker to create scoped sessions."""
    def __init__(self, session_maker, auto_commit=False):
        self.sessionmaker = session_maker
        self.auto_commit = auto_commit

    def __call__(self, *args):
        return ScopedSession(self.sessionmaker(*args), self.auto_commit)


LOCK = Lock()


class ModelManager(object):
    """
    ModelManager is the central class to create,list,get and delete models.
    ModelManager is mostly used to do the lookup from model name to the session
    cache which is given in each client's request.
    """
    def __init__(self, dbengine):
        self.engine = dbengine
        self.modelmaker = self._create_model_session()
        self.sessionmakers = {}

    def _create_model_session(self):
        """Create a session to read from the models table."""
        MODEL_BASE.metadata.create_all(self.engine)
        return ScopedSessionMaker(
            sessionmaker(
                bind=self.engine),
            auto_commit=True)

    @mutual_exclusive(LOCK)
    def create(self):
        """Create a new model entry in the database."""
        model_name = generate_model_handle()
        with self.modelmaker() as session:
            model = Model(
                handle=model_name,
                state="CREATED",
                created_at=datetime.datetime.utcnow(),
                watchdog_timer=datetime.datetime.utcnow(),
                etag_seed=generate_model_seed())
            session.add(model)
            self.sessionmakers[model.handle] = define_model(
                model.handle, self.engine, model.etag_seed)
            return model_name

    def get(self, model):
        """Get model data by name."""
        session_maker, data_access = self._get(model)
        return ScopedSession(session_maker()), data_access

    def _get(self, model):
        """Get model data by name internal."""
        if model not in self.models():
            raise KeyError(model)
        return self.sessionmakers[model]

    @mutual_exclusive(LOCK)
    def delete(self, model_name):
        """Delete a model entry in the database by name."""
        _, data_access = self.sessionmakers[model_name]
        del self.sessionmakers[model_name]
        with self.modelmaker() as session:
            session.query(Model).filter(Model.handle == model_name).delete()
        data_access.delete_all(self.engine)

    def models(self):
        """Return the list of models from the database."""
        with self.modelmaker() as session:
            return [model.handle for model in session.query(Model).all()]

    def model(self, model_name):
        """Get model from database by name."""
        with self.modelmaker() as session:
            return session.query(Model).filter(
                Model.handle == model_name).one()


def session_creator(model_name, filename=None, seed=None, echo=False):
    """Create a session maker for the model and db file."""
    if filename:
        engine = create_engine('sqlite:///{}'.format(filename))
    else:
        engine = create_engine('sqlite:///:memory:', echo=echo)
    if seed is None:
        seed = generate_model_seed()
    session_maker, data_access = define_model(model_name, engine, seed)
    return session_maker, data_access
