#!/usr/bin/env python

import datetime
import sqlalchemy
import os
import binascii
import collections
import logging
import struct
import hmac

from sqlalchemy import create_engine
from sqlalchemy import Column, Integer, String, Sequence, ForeignKey, Table, Text, DateTime, Enum, join, select, or_
from sqlalchemy.orm import relationship, state
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from __builtin__ import staticmethod

from utils import logcall

def generateModelHandle():
    return binascii.hexlify(os.urandom(16))

def generateModelSeed():
    return binascii.hexlify(os.urandom(16))

ModelBase = declarative_base()

class Model(ModelBase):
    __tablename__ = 'model'
    
    handle = Column(String, primary_key=True)
    state = Column(String)
    watchdog_timer = Column(DateTime)
    created_at = Column(DateTime)
    etag_seed = Column(String(32), nullable=False)
    
    def kick_watchdog(self, session):
        self.watchdog_timer = datetime.datetime.utcnow()
        session.commit()

    def set_inprogress(self, session):
        self.state = "INPROGRESS"
        session.commit()

    def set_done(self, session):
        self.state = "DONE"
        session.commit()

def define_model(model_name, dbengine, model_seed):
    Base = declarative_base()
    
    bindings_tablename = '{}_bindings'.format(model_name)
    roles_tablename = '{}_roles'.format(model_name)
    permissions_tablename = '{}_permissions'.format(model_name)
    members_tablename = '{}_members'.format(model_name)
    resources_tablename = '{}_resources'.format(model_name)
    
    role_permissions_tablename = '{}_role_permissions'.format(model_name)
    binding_members_tablename = '{}_binding_members'.format(model_name)
    group_members_tablename = '{}_group_members'.format(model_name)

    role_permissions = Table(role_permissions_tablename, Base.metadata,
        Column('roles_name', ForeignKey('{}.name'.format(roles_tablename)), primary_key=True),
        Column('permissions_name', ForeignKey('{}.name'.format(permissions_tablename)), primary_key=True),
    )

    binding_members = Table(binding_members_tablename, Base.metadata,
        Column('bindings_id', ForeignKey('{}.id'.format(bindings_tablename)), primary_key=True),
        Column('members_name', ForeignKey('{}.name'.format(members_tablename)), primary_key=True),
    )

    group_members = Table(group_members_tablename, Base.metadata,
        Column('group_name', ForeignKey('{}.name'.format(members_tablename)), primary_key=True),
        Column('members_name', ForeignKey('{}.name'.format(members_tablename)), primary_key=True),
    )

    class Resource(Base):
        __tablename__ = resources_tablename

        full_name = Column(String, primary_key=True)
        name = Column(String)
        type = Column(String)
        policy_update_counter = Column(Integer, default=0)

        parent_name = Column(String, ForeignKey('{}.name'.format(resources_tablename)))
        parent = relationship("Resource", remote_side=[name])
        bindings = relationship('Binding', back_populates="resource")

        def incrementUpdateCounter(self):
            self.policy_update_counter += 1

        def getEtag(self):
            msg = binascii.hexlify(struct.pack('>I',self.policy_update_counter)) + self.full_name
            return hmac.new(model_seed.encode('utf-8'), msg).hexdigest()

        def __repr__(self):
            return "<Resource(full_name='%s', type='%s')>" % (self.full_name, self.type)

    Resource.children = relationship(
        "Resource", order_by=Resource.name, back_populates="parent")

    class Member(Base):
        __tablename__ = members_tablename

        name = Column(String, primary_key=True)
        type = Column(String)
        member_name = Column(String)

        parents  = relationship('Member', secondary=group_members,
            primaryjoin=name==group_members.c.group_name,
            secondaryjoin=name==group_members.c.members_name)

        children = relationship('Member', secondary=group_members,
            primaryjoin=name==group_members.c.members_name,
            secondaryjoin=name==group_members.c.group_name)

        bindings = relationship('Binding',
            secondary=binding_members,
            back_populates='members')

        def __repr__(self):
            return "<Member(name='%s', type='%s')>" % (self.name, self.type)


    class Binding(Base):
        __tablename__ = bindings_tablename

        id = Column(Integer, Sequence('{}_id_seq'.format(bindings_tablename)), primary_key=True)

        resource_name = Column(Integer, ForeignKey('{}.name'.format(resources_tablename)))
        role_name = Column(Integer, ForeignKey('{}.name'.format(roles_tablename)))

        resource = relationship('Resource', remote_side=[resource_name])
        role = relationship('Role', remote_side=[role_name])

        members = relationship('Member',
            secondary=binding_members,
            back_populates='bindings')

        def __repr__(self):
            return "<Binding(id='%s', role='%s', resource='%s' members=%s)>" % (self.id, self.role_name, self.resource_name, self.members)

    class Role(Base):
        __tablename__ = roles_tablename

        name = Column(String, primary_key=True)
        permissions = relationship('Permission',
            secondary=role_permissions,
            back_populates='roles')

        def __repr__(self):
            return "<Role(name='%s')>" % (self.name)

    class Permission(Base):
        __tablename__ = permissions_tablename

        name = Column(String, primary_key=True)
        roles = relationship('Role',
            secondary=role_permissions,
            back_populates='permissions')

        def __repr__(self):
            return "<Permission(name='%s')>" % (self.name)

    class ModelAccess:
        TBL_BINDING = Binding
        TBL_MEMBER = Member
        TBL_PERMISSION = Permission
        TBL_ROLE = Role
        TBL_RESOURCE = Resource

        @staticmethod
        def deleteAll(engine):
            Binding.__table__.drop(engine)
            Member.__table__.drop(engine)
            Permission.__table__.drop(engine)
            Role.__table__.drop(engine)
            Resource.__table__.drop(engine)
            role_permissions.drop(engine)
            binding_members.drop(engine)
            group_members.drop(engine)

        @staticmethod
        def explain_granted(session, member_name, full_resource_name, role, permission):
            members, member_graph = ModelAccess.reverseExpandMembers(session, [member_name], request_graph=True)
            member_names = map(lambda m: m.name, members)
            resource_names = map(lambda r: r.full_name, ModelAccess.findResourcePath(session, full_resource_name))
            
            if role:
                roles = [role]
                qry = session.query(Binding, Member).join(binding_members).join(Member)
            else:
                roles = ModelAccess.getRolesByPermissionNames(session, [permission])
                qry = session.query(Binding, Member).join(binding_members).join(Member).join(Role).join(role_permissions).join(Permission)
            qry = qry.filter(Binding.role_name.in_(roles)).filter(Member.name.in_(member_names)).filter(Binding.resource_name.in_(resource_names))
            result = qry.all()
            if not result:
                raise Exception('Grant not found: ({},{},{})'.format(member_name, full_resource_name, role if role is not None else permission))
            else:
                bindings = [(b.resource_name, b.role_name, m.name) for b, m in result]
                return bindings, member_graph, resource_names

        @staticmethod
        def explain_denied(session, member_names, resource_names, permission_names, role_names):
            if not role_names:
                role_names = map(lambda r: r.name, ModelAccess.getRolesByPermissionNames(session, permission_names))
            # search for bindings granting the roles
            raise Exception('Not yet implemented')

        @staticmethod
        def query_access_by_member(session, member_name, permission_names, expand_resources=False, per_yield=1024):
            roles = ModelAccess.getRolesByPermissionNames(session, permission_names)
            qry = session.query(Binding).join(binding_members).join(Member)
            qry = qry.filter(Binding.role_name.in_(map(lambda r: r.name, roles)))
            qry = qry.filter(Member.name==member_name)
            bindings = qry.all()

            if expand_resources:
                def expand_resources(resource_names, depth=-1):
                    resource_names_set = set(resource_names)
                    if depth == 0 or len(resource_names) == 0:
                        return resource_names_set
                    else:
                        new_resource_names = set(map(lambda r: r.name, session.query(Resource).filter(Resource.parent_name.in_(resource_names)).all()))
                        return resource_names_set.union(expand_resources(new_resource_names, depth-1))
            else:
                def expand_resources(resource_names, depth=-1):
                    return resource_names

            return [(binding.role_name, expand_resources([binding.resource_name])) for binding in bindings]

        @staticmethod
        def query_access_by_resource(session, resource_name, permission_names, expand_groups=False):
            roles = ModelAccess.getRolesByPermissionNames(session, permission_names)
            resources = ModelAccess.findResourcePath(session, resource_name)
            bindings = session.query(Binding).filter(Binding.role_name.in_(map(lambda r: r.name, roles)), Binding.resource_name.in_(map(lambda r: r.name, resources))).all()

            role_member_mapping = collections.defaultdict(set)
            for binding in bindings:
                role_member_mapping[binding.role_name] = set(map(lambda m: m.name, binding.members))
            if expand_groups:
                for role in role_member_mapping:
                    role_member_mapping[role] = map(lambda m: m.name, ModelAccess.expandMembers(session, role_member_mapping[role]))

            return role_member_mapping

        @staticmethod
        def query_permissions_by_roles(session, role_names, role_prefixes, per_yield=1024):
            if not role_names and not role_prefixes:
                raise Exception('No roles or role prefixes specified')
            qry = session.query(Role, Permission).join(role_permissions).join(Permission)
            if role_names:
                qry = qry.filter(Role.name.in_(role_names))
            if role_prefixes:
                qry = qry.filter(or_(*[Role.name.startswith(prefix) for prefix in role_prefixes]))
            return qry.all()

        @staticmethod
        def denormalize(session, per_yield=1024):            
            for triples in session.query(Permission, Resource, Member).join(role_permissions).join(Role).join(Binding).join(binding_members).join(Member).yield_per(per_yield):
                yield triples

        @staticmethod
        def setIamPolicy(session, full_resource_name, policy):
            old_policy = ModelAccess.getIamPolicy(session, full_resource_name)
            if policy['etag'] != old_policy['etag']:
                raise Exception('Etags distinct, stored={}, provided={}'.format(old_policy['etag'], policy['etag']))

            old_policy = old_policy['bindings']
            policy = policy['bindings']
            additions = []
            subtractions = []

            def filterEtag(policy):
                return filter(lambda (k,v): k != 'etag', policy.iteritems())

            def calculateDiff(policy, old_policy):
                diff = collections.defaultdict(list)
                for role, members in filterEtag(policy):
                    if role in old_policy:
                        for member in members:
                            if member not in old_policy[role]:
                                diff[role].append(member)
                    else:
                        diff[role] = members
                return diff

            grants = calculateDiff(policy, old_policy)
            revocations = calculateDiff(old_policy, policy)

            for role, members in revocations.iteritems():
                bindings = session.query(Binding).filter(Binding.resource_name == full_resource_name).filter(Binding.role_name == role).join(binding_members).join(Member).filter(Member.name.in_(members)).all()
                map(lambda b: session.delete(b), bindings)
            for role, members in grants.iteritems():
                inserted = False
                existing_bindings = session.query(Binding).filter(Binding.resource_name == full_resource_name).filter(Binding.role_name == role).all()
                for binding in existing_bindings:
                    if binding.role_name == role:
                        inserted = True
                        for member in members:
                            binding.members.append(session.query(Member).filter(Member.name == member).one())
                if not inserted:
                    binding = Binding(resource_name=full_resource_name, role=session.query(Role).filter(Role.name==role).one())
                    binding.members = session.query(Member).filter(Member.name.in_(members)).all()
                    session.add(binding)
            resource = session.query(Resource).filter(Resource.full_name==full_resource_name).one()
            resource.incrementUpdateCounter()
            session.commit()

        @staticmethod
        def getIamPolicy(session, full_resource_name):
            resource = session.query(Resource).filter(Resource.full_name==full_resource_name).one()
            policy = {'etag':resource.getEtag(), 'bindings':{}, 'resource':resource.full_name}
            for binding in session.query(Binding).filter(Binding.resource_name==full_resource_name).all():
                role = binding.role_name
                members = map(lambda m: m.name, binding.members)
                policy['bindings'][role] = members
            return policy

        @staticmethod
        def checkIamPolicy(session, full_resource_name, permission_name, member_name):
            member_names = map(lambda m: m.name, ModelAccess.reverseExpandMembers(session, [member_name]))
            resource_names = map(lambda r: r.full_name, ModelAccess.findResourcePath(session, full_resource_name))
            return None != session.query(Permission).filter(Permission.name==permission_name).join(role_permissions).join(Role).join(Binding).filter(Binding.resource_name.in_(resource_names)).join(binding_members).join(Member).filter(Member.name.in_(member_names)).first()

        @staticmethod
        def listRolesByPrefix(session, role_prefix):
            return map(lambda r: r.name, session.query(Role).filter(Role.name.startswith(role_prefix)).all())

        @staticmethod
        def addRoleByName(session, role_name, permission_names):
            permission_names = set(permission_names)
            existing_permissions = session.query(Permission).filter(Permission.name.in_(permission_names)).all()
            for existing_permission in existing_permissions:
                try:
                    permission_names.remove(existing_permission.name)
                except KeyError:
                    pass

            new_permissions = map(lambda n: Permission(name=n), permission_names)
            map(session.add, new_permissions)
            ModelAccess.addRole(session, role_name, existing_permissions + new_permissions)
            session.commit()

        @staticmethod
        def delRoleByName(session, role_name):
            session.query(Role).filter(Role.name==role_name).delete()
            session.query(role_permissions).filter(role_permissions.roles_name==role_name).delete()
            session.commit()
        
        @staticmethod
        def addGroupMember(session, member_type_name, parent_type_names):
            type, name = member_type_name.split('/',1)
            parents = session.query(Member).filter(Member.name.in_(parent_type_names)).all()
            ModelAccess.addMember(session, member_type_name, parent_type_names)
            session.commit()

        @staticmethod
        def delGroupMember(session, member_type_name, parent_type_name, only_delete_relationship):
            if only_delete_relationship:
                session.query(group_members).filter(group_members.group_name==parent_type_name).filter(group_members.members_name==member_name).delete()
            else:
                #session.query(binding_members).filter(binding_members.c.members_name==member_name).delete()
                #session.query(group_members).filter(group_members.group_name==member_name).delete()
                session.query(Member).filter(Member.name==member_type_name).delete()
            session.commit()

        @staticmethod
        def listGroupMembers(session, member_name_prefix):
            return map(lambda m: m.name, session.query(Member).filter(Member.member_name.startswith(member_name_prefix)).all())

        @staticmethod
        def listResourcesByPrefix(session, full_resource_name_prefix):
            return map(lambda r: r.full_name, session.query(Resource).filter(Resource.full_name.startswith(full_resource_name_prefix)).all())

        @staticmethod
        def delResourceByName(session, full_resource_name):
            expanded_resources = ModelAccess.expandResources(session, [full_resource_name])
            session.query(Binding).filter(Binding.resource_name.in_(map(lambda r: r.full_name, expanded_resources))).delete()
            map(lambda r: session.delete(r), expanded_resources)
            session.commit()

        @staticmethod
        def addResourceByName(session, full_name, full_parent_name, no_require_parent):
            if not no_require_parent:
                parent = session.query(Resource).filter(Resource.full_name==full_parent_name).one()
            else:
                parent = None
            return ModelAccess.addResource(session, full_name, parent)

        @staticmethod    
        def addResource(session, name, parent=None):
            resource = Resource(full_name=name, name=name, type='test', parent=parent)
            session.add(resource)
            return resource

        @staticmethod
        def addRole(session, name, permissions=[]):
            role = Role(name=name, permissions=permissions)
            session.add(role)
            return role

        @staticmethod
        def addPermission(session, name, roles=[]):
            permission = Permission(name=name, roles=roles)
            session.add(permission)
            return permission

        @staticmethod
        def addBinding(session, resource, role, members):
            binding = Binding(resource=resource, role=role, members=members)
            session.add(binding)
            return binding

        @staticmethod
        def addMember(session, type_name, parent_type_names=[]):
            type, name = type_name.split('/',1)
            parents = session.query(Member).filter(Member.name.in_(parent_type_names)).all()
            if len(parents) != len(parent_type_names):
                raise Exception("At least one parent not found")
            member = Member(name=type_name,member_name=name, type=type, parents=parents)
            session.add(member)
            return member

        @staticmethod
        def checkAccess(session, member_name, permission_name, resource_name):
            raise NotImplementedError()

        @staticmethod
        def expandResources(session, full_resource_names):
            resources = session.query(Resource).filter(Resource.full_name.in_(full_resource_names)).all()
            new_resource_set = set()
            resource_set = set()
            
            def addToSets(resources):
                for resource in resources:
                    if resource not in resource_set:
                        new_resource_set.add(resource)
                        resource_set.add(resource)
            
            while len(new_resource_set) > 0:
                resources_to_walk = new_resource_set
                new_resource_set = set()
                for resource in resources_to_walk:
                    addToSets(resource.children)
                    
            return resource_set
            
        @staticmethod
        def reverseExpandMembers(session, member_names, request_graph=False):
            members = session.query(Member).filter(Member.name.in_(member_names)).all()
            membership_graph = collections.defaultdict(set)

            def isGroup(member):
                return member.type == 'group'

            member_set = set()
            new_member_set = set()

            def addToSets(members, child):
                for member in members:
                    if request_graph and child:
                        membership_graph[child.name].add(member.name)
                    if request_graph and not child:
                        membership_graph[member.name]
                    if member not in member_set:
                        new_member_set.add(member)
                        member_set.add(member)

            addToSets(members, None)
            while len(new_member_set) > 0:
                members_to_walk = new_member_set
                new_member_set = set()
                for member in members_to_walk:
                    addToSets(member.parents, member)
                    
            if request_graph:
                return member_set, membership_graph
            else:
                return member_set

        @staticmethod
        def expandMembers(session, member_names):
            members = session.query(Member).filter(Member.name.in_(member_names)).all()

            def isGroup(member):
                return member.type == 'group'

            group_set = set()
            non_group_set = set()
            new_group_set = set()

            def addToSets(members):
                for member in members:
                    if isGroup(member):
                        if member not in group_set:
                            new_group_set.add(member)
                        group_set.add(member)
                    else:
                        non_group_set.add(member)

            addToSets(members)

            while len(new_group_set) > 0:
                groups_to_walk = new_group_set
                new_group_set = set()
                for group in groups_to_walk:
                    addToSets(group.children)

            return group_set.union(non_group_set)

        @staticmethod
        def findResourcePath(session, full_resource_name):
            resources = session.query(Resource).filter(Resource.full_name == full_resource_name).all()
            if len(resources) < 1:
                return []

            path = []
            resource = resources[0]

            path.append(resource)
            while resource.parent:
                resource = resource.parent
                path.append(resource)

            return path

        @staticmethod
        def getRolesByPermissionNames(session, permission_names):
            permission_set = set(permission_names)
            permissions = session.query(Permission).filter(Permission.name.in_(permission_set)).all()

            roles = set()
            for permission in permissions:
                for role in permission.roles:
                    roles.add(role)

            result_set = set()
            for role in roles:
                role_permissions = set(map(lambda permission: permission.name, role.permissions))
                if permission_set.issubset(role_permissions):
                    result_set.add(role)

            return result_set

        @staticmethod
        def getMember(session, name):
            return session.query(Member).filter(Member.name == name).all()

    Base.metadata.create_all(dbengine)
    return sessionmaker(bind=dbengine), ModelAccess

def undefine_model(sessionmaker, data_access):
    session = sessionmaker()
    data_access.deleteAll(session)

class ScopedSession(object):
    def __init__(self, session, auto_commit=False):
        self.session = session
        self.auto_commit = auto_commit

    def __enter__(self):
        return self.session

    def __exit__(self, type, value, traceback):
        try:
            if traceback is None and self.auto_commit:
                self.session.commit()
        finally:
            self.session.close()
        
class ScopedSessionMaker(object):
    def __init__(self, sessionmaker, auto_commit=False):
        self.sessionmaker = sessionmaker
        self.auto_commit = auto_commit
        
    def __call__(self, *args):
        return ScopedSession(self.sessionmaker(*args), self.auto_commit)

class ModelManager:
    def __init__(self, dbengine):
        self.engine = dbengine
        self.modelmaker = self._create_model_session()
        self.sessionmakers = {}
    
    def _create_model_session(self):
        ModelBase.metadata.create_all(self.engine)
        return ScopedSessionMaker(sessionmaker(bind=self.engine), auto_commit=True)
    
    def create(self):
        model_name = generateModelHandle()
        with self.modelmaker() as session:
            model = Model(handle=model_name, state="CREATED", created_at=datetime.datetime.utcnow(), watchdog_timer=datetime.datetime.utcnow(), etag_seed=generateModelSeed())
            session.add(model)
            self.sessionmakers[model.handle] = define_model(model.handle, self.engine, model.etag_seed)
            return model_name

    def get(self, model):
        sessionmaker, data_access = self._get(model)
        return ScopedSession(sessionmaker()), data_access

    def _get(self, model):
        if not model in self.models():
            raise KeyError(model)
        
        try:
            return self.sessionmakers[model]
        except KeyError:
            self.sessionmakers[model] = define_model(model, self.engine)
            return self.sessionmakers[model]
    
    def delete(self, model_name):
        sessionmaker, data_access = self.sessionmakers[model_name]
        del self.sessionmakers[model_name]
        with self.modelmaker() as session:
            session.query(Model).filter(Model.handle == model_name).delete()
            session.commit()
        data_access.deleteAll(self.engine)

    def models(self):
        with self.modelmaker() as session:
            return map(lambda model: model.handle, session.query(Model).all())
    
    def model(self, model_name):
        with self.modelmaker() as session:
            return session.query(Model).filter(Model.handle == model_name).one()

def session_creator(model_name, filename=None):
    if filename:
        engine = create_engine('sqlite:///%s'%filename)
    else:
        engine = create_engine('sqlite:///:memory:', echo=True)
        
    sessionmaker, data_access = define_model(model_name, engine)
    return sessionmaker, data_access

def explainMemberHasAccessTo(session, data_access, member_names, expand_resources=False):
    if expand_resources:
        raise NotImplementedError()

    members = data_access.reverseExpandMembers(session, member_names)
    return session.query(data_access.TBL_RESOURCE).join(data_access.TBL_RESOURCE.bindings).join(data_access.TBL_BINDING.members).filter(data_access.TBL_MEMBER.name.in_(map(lambda m: m.name, members))).join(data_access.TBL_BINDING.role).all()

def explainHasAccessToResource(session, data_access, resource_name, permission_names, expand_groups=False):
    roles = data_access.getRolesByPermissionNames(session, permission_names)
    resources = data_access.findResourcePath(session, resource_name)
    bindings = session.query(data_access.TBL_BINDING).filter(data_access.TBL_BINDING.role_name.in_(map(lambda r: r.name, roles)), data_access.TBL_BINDING.resource_name.in_(map(lambda r: r.name, resources))).all()

    member_set = set()
    for binding in bindings:
        for member in binding.members:
            member_set.add(member)

    if not expand_groups:
        members = member_set
    else:
        members = data_access.expandMembers(session, map(lambda m: m.name, member_set))
    return members

def useScenario(session, data_access):
    print explainHasAccessToResource(session, data_access, 'vm1', ['cloudsql.table.read'], True)
    print explainHasAccessToResource(session, data_access, 'project', ['cloudsql.table.read'], False)
    print explainMemberHasAccessTo(session, data_access, ['group1'], False)

if __name__ == "__main__":
    def createScenario(session, data_access):
        project = data_access.addResource(session, 'project')
        vm = data_access.addResource(session, 'vm1', project)
        db = data_access.addResource(session, 'db1', project)

        permission1 = data_access.addPermission(session, 'cloudsql.table.read')
        permission2 = data_access.addPermission(session, 'cloudsql.table.write')

        role1 = data_access.addRole(session, 'sqlreader', [permission1])
        role2 = data_access.addRole(session, 'sqlwriter', [permission1, permission2])

        group1 = data_access.addMember(session, 'group1', 'group')
        group2 = data_access.addMember(session, 'group2', 'group', [group1]) 

        member1 = data_access.addMember(session, 'felix', 'user', [group2])
        member2 = data_access.addMember(session, 'fooba', 'user', [group2])

        binding = data_access.addBinding(session, vm, role1, [group1])
        binding = data_access.addBinding(session, project, role2, [group2])
        session.commit()
    
    engine = create_engine('sqlite:///:memory:', echo=True)
    model_manager = ModelManager(engine)
    
    model_name = model_manager.create()
    creator, data_access = model_manager.get(model_name)
    session = creator()
    createScenario(session, data_access)
    useScenario(session, data_access)
    
    model_name = model_manager.create()
    creator, data_access = model_manager.get(model_name)
    session = creator()
    createScenario(session, data_access)
    useScenario(session, data_access)
    
    model_manager.delete(model_name)
    print model_manager.models()
