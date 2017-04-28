#!/usr/bin/env python

import datetime
import utils
import sqlalchemy
from sqlalchemy import create_engine
from sqlalchemy import Column, Integer, String, Sequence, ForeignKey, Table, Text, DateTime, Enum
from sqlalchemy.orm import relationship, state
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()

role_permissions = Table('role_permissions', Base.metadata,
		Column('roles_name', ForeignKey('roles.name'), primary_key=True),
		Column('permissions_name', ForeignKey('permissions.name'), primary_key=True),
	)

binding_members = Table('binding_members', Base.metadata,
		Column('bindings_id', ForeignKey('bindings.id'), primary_key=True),
		Column('members_name', ForeignKey('members.name'), primary_key=True),
	)

group_members = Table('group_members', Base.metadata,
		Column('group_name', ForeignKey('members.name'), primary_key=True),
		Column('members_name', ForeignKey('members.name'), primary_key=True),
	)

class ModelState(Enum):
	WAITING = "WAITING"
	INPROGRESS = "INPROGRESS"
	DONE = "DONE"

class Model(Base):
	__tablename__ = 'model'
	
	handle = Column(String, primary_key=True)
	state = Column(ModelState)
	watchdog_timer = Column(DateTime)
	created_at = Column(DateTime)
	
	def kick_watchdog(self, session):
		self.watchdog_timer = datetime.datetime.utcnow()
		session.commit()

	def set_inprogress(self, session):
		self.state = ModelState.INPROGRESS
		session.commit()

	def set_done(self, session):
		self.state = ModelState.DONE
		session.commit()

class Resource(Base):
	__tablename__ = 'resources'

	name = Column(String, primary_key=True)
	type = Column(String)

	parent_name = Column(String, ForeignKey('resources.name'))
	parent = relationship("Resource", remote_side=[name])

	bindings = relationship('Binding', back_populates="resource")

	def __repr__(self):
		return "<Resource(name='%s', type='%s')>" % (self.name, self.type)

Resource.children = relationship(
	"Resource", order_by=Resource.name, back_populates="parent")

class Member(Base):
	__tablename__ = 'members'

	name = Column(String, primary_key=True)
	type = Column(String)

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
	__tablename__ = 'bindings'

	id = Column(Integer, Sequence('bindings_id_seq'), primary_key=True)

	resource_name = Column(Integer, ForeignKey('resources.name'))
	role_name = Column(Integer, ForeignKey('roles.name'))

	resource = relationship('Resource', remote_side=[resource_name])
	role = relationship('Role', remote_side=[role_name])

	members = relationship('Member',
				secondary=binding_members,
				back_populates='bindings')

	def __repr__(self):
		return "<Binding(id='%s')>" % (self.id)

class Role(Base):
	__tablename__ = 'roles'

	name = Column(String, primary_key=True)
	permissions = relationship('Permission',
				secondary=role_permissions,
				back_populates='roles')

	def __repr__(self):
		return "<Role(name='%s')>" % (self.name)

class Permission(Base):
	__tablename__ = 'permissions'

	name = Column(String, primary_key=True)
	roles = relationship('Role',
				secondary=role_permissions,
				back_populates='permissions')

	def __repr__(self):
		return "<Permission(name='%s')>" % (self.name)

def createSession():
	engine = create_engine('sqlite:///:memory:', echo=True)
	Base.metadata.create_all(engine)
	Session = sessionmaker(bind=engine)
	session = Session()
	return session

def session_creator(filename=None):
	if filename:
		engine = create_engine('sqlite:///%s'%filename)
	else:
		raise NotImplementedError(filename)
		engine = create_engine('sqlite:///:memory:', echo=True)
	Base.metadata.create_all(engine)
	return sessionmaker(bind=engine)

def addResource(session, name, parent=None):
	resource = Resource(name=name, type='test', parent=parent)
	session.add(resource)
	return resource

def addRole(session, name, permissions=[]):
	role = Role(name=name, permissions=permissions)
	session.add(role)
	return role

def addPermission(session, name, roles=[]):
	permission = Permission(name=name, roles=roles)
	session.add(permission)
	return permission

def addBinding(session, resource, role, members):
	binding = Binding(resource=resource, role=role, members=members)
	session.add(binding)
	return binding

def addMember(session, name, type, parents=[]):
	member = Member(name=name, type=type, parents=parents)
	session.add(member)
	return member

def checkAccess(session, member_name, permission_name, resource_name):
	pass

def reverseExpandMembers(session, member_names):
	members = session.query(Member).filter(Member.name.in_(member_names)).all()

	def isGroup(member):
		return member.type == 'group'

	member_set = set()
	new_member_set = set()

	def addToSets(members):
		for member in members:
			if member not in member_set:
				new_member_set.add(member)
				member_set.add(member)

	addToSets(members)
	while len(new_member_set) > 0:
		members_to_walk = new_member_set
		new_member_set = set()
		for member in members_to_walk:
			addToSets(member.parents)
	return member_set

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

def findResourcePath(session, resource_name):
	resources = session.query(Resource).filter(Resource.name == resource_name).all()
	if len(resources) < 1:
		return []

	path = []

	resource = resources[0]

	path.append(resource)
	while resource.parent:
		resource = resource.parent
		path.append(resource)

	return path

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

def getMember(session, name):
	return session.query(Member).filter(Member.name == name).all()

def createScenario(session):
	project = addResource(session, 'project')
	vm = addResource(session, 'vm1', project)
	db = addResource(session, 'db1', project)

	permission1 = addPermission(session, 'cloudsql.table.read')
	permission2 = addPermission(session, 'cloudsql.table.write')

	role1 = addRole(session, 'sqlreader', [permission1])
	role2 = addRole(session, 'sqlwriter', [permission1, permission2])

	group1 = addMember(session, 'group1', 'group')
	group2 = addMember(session, 'group2', 'group', [group1]) 

	member1 = addMember(session, 'felix', 'user', [group2])
	member2 = addMember(session, 'fooba', 'user', [group2])

	binding = addBinding(session, vm, role1, [group1])
	binding = addBinding(session, project, role2, [group2])
	session.commit()

def explainMemberHasAccessTo(session, member_names, expand_resources=False):
    if expand_resources:
        raise NotImplementedError()

    members = reverseExpandMembers(session, member_names)
    return session.query(Resource).join(Resource.bindings).join(Binding.members).filter(Member.name.in_(map(lambda m: m.name, members))).join(Binding.role).all()

def explainHasAccessToResource(session, resource_name, permission_names, expand_groups=False):
    roles = getRolesByPermissionNames(session, permission_names)
    resources = findResourcePath(session, resource_name)
    bindings = session.query(Binding).filter(Binding.role_name.in_(map(lambda r: r.name, roles)), Binding.resource_name.in_(map(lambda r: r.name, resources))).all()

    member_set = set()
    for binding in bindings:
        for member in binding.members:
            member_set.add(member)

    if not expand_groups:
        members = member_set
    else:
        members = expandMembers(session, map(lambda m: m.name, member_set))
	return members

def create_model(session):
	handle = utils.generateModelHandle()
	return Model(handle=handle, state=ModelState.WAITING, created_at=datetime.datetime.utcnow())

def useScenario(session):
    print explainHasAccessToResource(session, 'vm1', ['cloudsql.table.read'], True)
    print explainHasAccessToResource(session, 'project', ['cloudsql.table.read'], False)
    print explainMemberHasAccessTo(session, ['group1'], False)


if __name__ == "__main__":
    session = createSession()
    createScenario(session)
    useScenario(session)

