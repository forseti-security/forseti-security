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

"""Unit Tests: Database abstraction objects for Forseti Server."""

from collections import defaultdict
import unittest
from sqlalchemy.orm.exc import NoResultFound
from tests.unittest_utils import ForsetiTestCase
from tests.services import test_models
from tests.services.model_tester import ModelCreator
from tests.services.model_tester import ModelCreatorClient
from google.cloud.forseti.common.util import logger
from google.cloud.forseti.services.dao import session_creator

LOGGER = logger.get_logger(__name__)


class DaoTest(ForsetiTestCase):
  """General data abstraction layer use case tests."""

  def setUp(self):
    """Setup."""
    pass

  def test_repr_dao_objects(self):
    """Test __repr__ methods of dao objects."""
    _, data_access = session_creator('test')
    data_access.TBL_BINDING(role_name='role').__repr__()
    data_access.TBL_MEMBER(name='test', type='group').__repr__()
    data_access.TBL_PERMISSION(name='permission').__repr__()
    data_access.TBL_ROLE(name='role').__repr__()
    data_access.TBL_RESOURCE(full_name='full_name', type='test').__repr__()

  def test_list_roles_by_prefix(self):
    """Test list_roles_by_prefix."""
    session_maker, data_access = session_creator('test')
    session = session_maker()
    client = ModelCreatorClient(session, data_access)
    _ = ModelCreator(test_models.ROLES_PREFIX_TESTING_1, client)

    expectations = {
        '': {
            'cloud.admin', 'cloud.reader', 'cloud.writer', 'db.viewer',
            'db.writer'
        },
        'cloud': {
            'cloud.admin',
            'cloud.reader',
            'cloud.writer',
        },
        'db': {
            'db.viewer',
            'db.writer',
        },
        'admin': set(),
    }

    for prefix, expected_roles in expectations.iteritems():
      role_names = data_access.list_roles_by_prefix(session, prefix)
      self.assertEqual(expected_roles, set(role_names))

  def test_add_role_by_name(self):
    """Test add_role_by_name."""
    session_maker, data_access = session_creator('test')
    session = session_maker()
    client = ModelCreatorClient(session, data_access)
    _ = ModelCreator(test_models.ROLES_PREFIX_TESTING_1, client)

    # Check that initially nothing is found
    res = data_access.list_roles_by_prefix(session, 'test')
    self.assertEqual(set(), set(res))

    # Add a new role
    data_access.add_role_by_name(session, u'test_role', ['perm1'])
    res = data_access.list_roles_by_prefix(session, 'test')
    self.assertEqual(set([u'test_role']), set(res))

    # Get role by permission to check it's queryable
    res = data_access.get_roles_by_permission_names(session, ['perm1'])
    res = [r.name for r in res]
    self.assertEqual(set([u'test_role']), set(res))

  def test_add_group_member(self):
    """Test add_group_member."""
    session_maker, data_access = session_creator('test')
    session = session_maker()
    client = ModelCreatorClient(session, data_access)
    _ = ModelCreator(test_models.MEMBER_TESTING_2, client)

    memberships = [
        ('group/t4', ['group/g3g2g1', 'group/g3']),
        ('group/t5', ['group/t4']),
        ('user/t1', ['group/g1']),
        ('user/t2', ['group/g2', 'group/g3']),
        ('user/t3', ['group/g3g2g1', 'group/g3']),
        ('user/t6', ['group/t5', 'group/t4']),
    ]

    checks = {
        'user/t1': ['group/g1'],
        'user/t2': ['group/g2', 'group/g3'],
        'user/t3': ['group/g3g2'],
        'group/t5': ['group/g3g2'],
    }

    for member, parents in memberships:
      data_access.add_group_member(session, member, parents)

    for member, groups in checks.iteritems():
      res = data_access.reverse_expand_members(session, [member])
      res = [m.name for m in res]
      for group in groups:
        self.assertTrue(group in res)

  def test_list_group_members(self):
    """Test listing of group members."""
    session_maker, data_access = session_creator('test')
    session = session_maker()
    client = ModelCreatorClient(session, data_access)
    _ = ModelCreator(test_models.MEMBER_TESTING_2, client)

    all_member_names = data_access.list_group_members(session, '')
    checks = {
        u'group/g1', u'group/g2', u'group/g3', u'user/u1', u'user/u2',
        u'group/g3g2', u'group/g3g2g1'
    }

    for check in checks:
      self.assertTrue(check in all_member_names)

  def test_list_group_members_by_member_type(self):
    """Test listing of group members."""
    session_maker, data_access = session_creator('test')
    session = session_maker()
    client = ModelCreatorClient(session, data_access)
    _ = ModelCreator(test_models.MEMBER_TESTING_2, client)
    member_types = ['user']

    all_member_names = data_access.list_group_members(
        session, '', member_types=member_types)
    checks = {u'user/u1', u'user/u2'}
    self.assertEqual(checks, set(all_member_names))

  def test_iter_groups(self):
    """Test fetching all groups in model."""
    session_maker, data_access = session_creator('test')
    session = session_maker()
    client = ModelCreatorClient(session, data_access)
    _ = ModelCreator(test_models.MEMBER_TESTING_2, client)

    group_members = data_access.iter_groups(session)
    group_member_names = set((g.name for g in group_members))

    all_member_names = {
        u'group/g1', u'group/g2', u'group/g3', u'user/u1', u'user/u2',
        u'group/g3g2', u'group/g3g2g1'
    }
    group_checks = set((c for c in all_member_names if c.startswith('group/')))
    user_checks = set((c for c in all_member_names if c.startswith('user/')))

    for group in group_checks:
      self.assertTrue(group in group_member_names,
                      'Members: %s should contain %s' % (
                          group_member_names, group))

    for user in user_checks:
      self.assertFalse(user in group_member_names,
                       'Members: %s, should not contain %s' % (
                           group_member_names, user))

  def test_list_resources_by_prefix(self):
    """Test listing of resources."""
    session_maker, data_access = session_creator('test')
    session = session_maker()
    client = ModelCreatorClient(session, data_access)
    _ = ModelCreator(test_models.RESOURCE_EXPANSION_1, client)

    check_resources = {u'r/res{}'.format(i) for i in range(1, 9)}
    resources = data_access.list_resources_by_prefix(session, name_prefix='')
    resource_type_names = [r.type_name for r in resources]
    self.assertEqual(check_resources, set(resource_type_names))

    resources = data_access.list_resources_by_prefix(session,
                                                     name_prefix='res8')
    resource_type_names = [r.type_name for r in resources]
    self.assertEqual(set([u'r/res8']), set(resource_type_names))

    resources = data_access.list_resources_by_prefix(session,
                                                     name_prefix='res89')
    resource_type_names = [r.type_name for r in resources]
    self.assertEqual(set(), set(resource_type_names))

  def test_add_resource_by_name(self):
    """Test add_resource_by_name."""
    session_maker, data_access = session_creator('test')
    session = session_maker()
    client = ModelCreatorClient(session, data_access)
    _ = ModelCreator(test_models.RESOURCE_EXPANSION_1, client)

    data_access.add_resource_by_name(session, 'r/res9', 'r/res1', False)
    data_access.add_resource_by_name(session, 'r/res10', 'r/res9', False)
    data_access.add_resource_by_name(session, 'r/res11', 'r/res3', False)

    self.assertRaises(NoResultFound,
                      lambda: data_access.add_resource_by_name(
                          session, 'r/res14', 'r/res13', False))
    self.assertTrue(
        11 == len(data_access.list_resources_by_prefix(session, '')))

  def test_reverse_expand_members(self):
    session_maker, data_access = session_creator('test')
    session = session_maker()
    client = ModelCreatorClient(session, data_access)
    _ = ModelCreator(test_models.MEMBER_TESTING_2, client)

    members = data_access.reverse_expand_members(session,
                                                 ['group/g2', 'group/g3'])

    members = set([m.name for m in members])
    self.assertEqual(set([u'group/g2', u'group/g3']), members)

    members = data_access.reverse_expand_members(session,
                                                 ['group/g3g2g1'])
    members = set([m.name for m in members])
    self.assertEqual(set([
        u'group/g3',
        u'group/g3g2',
        u'group/g3g2g1',
        u'group/g2']), members)

    members = data_access.reverse_expand_members(session,
                                                 ['group/g3g2g1', 'group/g1'])
    members = set([m.name for m in members])
    self.assertEqual(set([
        u'group/g3',
        u'group/g3g2',
        u'group/g3g2g1',
        u'group/g2',
        u'group/g1']), members)

    members = data_access.reverse_expand_members(session,
                                                 ['group/g1'])
    members = set([m.name for m in members])
    self.assertEqual(set([
        u'group/g1']), members)

  def test_reverse_expand_members_special_groups(self):
    session_maker, data_access = session_creator('test')
    session = session_maker()
    client = ModelCreatorClient(session, data_access)
    _ = ModelCreator(test_models.COMPLEX_MODEL, client)

    members = data_access.reverse_expand_members(session,
                                                 ['user/b'])

    members = set([m.name for m in members])
    self.assertEqual(set([
        u'allauthenticatedusers',
        u'group/a',
        u'projecteditor/project1',
        u'user/b',
        ]), members)

    # Unknown members expand to allauthenticatedusers
    members = data_access.reverse_expand_members(session,
                                                 ['user/unknown'])

    members = set([m.name for m in members])
    self.assertEqual(set([
        u'allauthenticatedusers',
        ]), members)

  def test_expand_members(self):
    """Test expand_members."""
    session_maker, data_access = session_creator('test')
    session = session_maker()
    client = ModelCreatorClient(session, data_access)
    _ = ModelCreator(test_models.MEMBER_TESTING_2, client)

    members = data_access.expand_members(session, ['group/g1', 'group/g3'])
    members = set([m.name for m in members])

    self.assertEqual(set([
        u'group/g1',
        u'group/g3',
        u'group/g3g2',
        u'group/g3g2g1'
        ]), members)

    members = data_access.expand_members(session, ['group/g1', 'group/g2'])
    members = set([m.name for m in members])

    self.assertEqual(set([
        u'group/g1',
        u'group/g2',
        u'group/g3g2g1'
        ]), members)

  def test_expand_members_special_groups(self):
    """Test expand_members with special groups."""
    session_maker, data_access = session_creator('test')
    session = session_maker()
    client = ModelCreatorClient(session, data_access)
    _ = ModelCreator(test_models.COMPLEX_MODEL, client)
    members = data_access.expand_members(session, ['projectviewer/project2',
                                                   'projecteditor/project1',
                                                   'projectowner/project1'])
    members = set([m.name for m in members])
    self.assertEqual(set([
        u'group/b',
        u'group/c',
        u'projecteditor/project1',
        u'projectowner/project1',
        u'projectviewer/project2',
        u'user/a',
        u'user/b',
        u'user/d',
        u'user/e',
        u'user/f',
        ]), members)

  def test_expand_members_map(self):
    """Test expand_members_map."""
    session_maker, data_access = session_creator('test')
    session = session_maker()
    client = ModelCreatorClient(session, data_access)
    _ = ModelCreator(test_models.MEMBER_TESTING_3, client)

    members_map = data_access.expand_members_map(session, ['group/g1'])
    self.assertEqual(
        set([
            u'group/g1',
            u'group/g1g1',
            u'user/g1g1u1',
            u'user/g1g1u2',
            u'user/g1g1u3',
        ]), members_map[u'group/g1'])

  def test_expand_members_map_special_groups(self):
    """Test expand_members_map with special groups."""
    session_maker, data_access = session_creator('test')
    session = session_maker()
    client = ModelCreatorClient(session, data_access)
    _ = ModelCreator(test_models.COMPLEX_MODEL, client)
    members_map = data_access.expand_members_map(session,
                                                 ['projecteditor/project1'])

    self.assertEqual(set([
        'projecteditor/project1',
        u'group/b',
        u'group/c',
        u'user/a',
        u'user/b',
        u'user/d',
        u'user/f',
        ]), members_map['projecteditor/project1'])

  def test_explain_granted(self):
    """Test explain_granted."""
    session_maker, data_access = session_creator('test')
    session = session_maker()
    client = ModelCreatorClient(session, data_access)
    _ = ModelCreator(test_models.EXPLAIN_GRANTED_1, client)

    callable = lambda: data_access.explain_granted(
        session, 'user/u3', 'r/res1', 'admin', None)
    self.assertRaises(Exception, callable)
    callable = lambda: data_access.explain_granted(
        session, 'user/u3', 'r/res1', None, 'delete')
    self.assertRaises(Exception, callable)

    check_1 = {
        'parameters': ('user/u3', 'r/res4', None, 'read'),
        'bindings': [
            ('r/res1', 'viewer', 'group/g1'),
            ('r/res3', 'viewer', 'group/g1'),
            ('r/res3', 'writer', 'group/g3'),
        ],
        'member_graph': {
            'user/u3': set(['group/g3g1', 'group/g2', 'group/g1']),
            'group/g3g1': set(['group/g3']),
        },
        'ancestors': ['r/res4', 'r/res3', 'r/res1']
    }

    check_2 = {
        'parameters': ('user/u4', 'r/res4', None, 'write'),
        'bindings': [('r/res3', 'writer', 'group/g3'),],
        'member_graph': {
            'user/u4': set(['group/g3g1']),
            'group/g3g1': set(['group/g3']),
        },
        'ancestors': ['r/res4', 'r/res3', 'r/res1']
    }

    check_3 = {
        'parameters': ('user/u1', 'r/res1', 'admin', None),
        'bindings': [('r/res1', 'admin', 'user/u1'),],
        'member_graph': {
            'user/u1': set([]),
        },
        'ancestors': ['r/res1',]
    }

    def test_scenario(checks):
      """Test a declarative explanation scenario."""
      user, resource, role, permission = checks['parameters']
      explanation = data_access.explain_granted(session,
                                                user,
                                                resource,
                                                role,
                                                permission)
      bindings, graph, ancestors = explanation
      bindings = checks['bindings']
      member_graph = checks['member_graph']
      check_ancestors = checks['ancestors']
      for check in bindings:
        self.assertTrue(check in bindings)
      self.assertEqual(set(member_graph.keys()), set(graph.keys()))
      for key, value in member_graph.iteritems():
        self.assertEqual(value, graph[key])
      self.assertEqual(check_ancestors, ancestors)

    test_scenario(check_1)
    test_scenario(check_2)
    test_scenario(check_3)

  def test_explain_denied(self):
    """Test explain_denied."""
    session_maker, data_access = session_creator('test')
    session = session_maker()
    client = ModelCreatorClient(session, data_access)
    _ = ModelCreator(test_models.EXPLAIN_GRANTED_1, client)

    def explain_denied(member_name, resource_names,
                       permission_names, role_names):
      """data_access.explain_denied wrapper."""
      return data_access.explain_denied(session,
                                        member_name,
                                        resource_names,
                                        permission_names,
                                        role_names)

    explanation = explain_denied('user/u4',
                                 ['r/res2',
                                  'r/res3'],
                                 ['delete'],
                                 None)
    expectation = [
        (0, [(u'admin', u'user/u4', u'r/res1')]),
    ]
    self.assertEqual(expectation, explanation)

    explanation = explain_denied('user/u2',
                                 ['r/res4'],
                                 ['read'],
                                 None)
    expectation = [
        (2, [(u'admin', u'user/u2', u'r/res1')]),
        (2, [(u'viewer', u'user/u2', u'r/res1')]),
        (2, [(u'writer', u'user/u2', u'r/res1')]),
        (1, [(u'admin', u'user/u2', u'r/res3')]),
        (1, [(u'viewer', u'user/u2', u'r/res3')]),
        (1, [(u'writer', u'user/u2', u'r/res3')]),
        (0, [(u'admin', u'user/u2', u'r/res4')]),
        (0, [(u'viewer', u'user/u2', u'r/res4')]),
        (0, [(u'writer', u'user/u2', u'r/res4')]),
        (0, [(u'admin', u'group/g2', u'r/res4')]),
        (2, [(u'viewer', u'group/g1', u'r/res1')]),
        (1, [(u'viewer', u'group/g1', u'r/res3')]),
        (1, [(u'writer', u'group/g3', u'r/res3')])
    ]

    self.assertEqual(len(expectation), len(explanation))
    for item in expectation:
      self.assertIn(item, explanation)

  def test_denorm_group_in_group(self):
    """Test group_in_group denormalization."""
    session_maker, data_access = session_creator('test')
    session = session_maker()
    client = ModelCreatorClient(session, data_access)
    _ = ModelCreator(test_models.GROUP_IN_GROUP_TESTING_1, client)

    iterations = data_access.denorm_group_in_group(session)
    self.assertEqual(iterations,
                     4,
                     'Denormalization should have taken 4 iterations.')

    expected = [
        (u'group/g2', u'group/g2g1'),
        (u'group/g3', u'group/g1'),
        (u'group/g3', u'group/g2'),
        (u'group/g4', u'group/g1'),
        (u'group/g4', u'group/g3'),
        (u'group/g5', u'group/g4'),
        (u'group/g6', u'group/g5'),
        (u'group/g7', u'group/g6'),
    ]

    def transitive_closure(expected):
      relation = set()
      for item in expected:
        relation.add(item)
      size = 0
      while size < len(relation):
        size = len(relation)
        to_add = set()
        for p1, g1 in relation:
          for p2, g2 in relation:
            if p2 == g1:
              to_add.add((p1, g2))
        for item in to_add:
          relation = relation.union(to_add)
      return relation
    expected = transitive_closure(expected)

    entries = session.query(data_access.TBL_GROUP_IN_GROUP).all()
    denormed_set = set([(i.parent, i.member) for i in entries])
    self.assertEqual(
        expected,
        denormed_set,
        'Denormalized should be equivalent to transitive closure')

  def test_query_access_by_permission(self):
    """Test query_access_by_permission."""
    session_maker, data_access = session_creator('test')
    session = session_maker()
    client = ModelCreatorClient(session, data_access)
    _ = ModelCreator(test_models.ACCESS_BY_PERMISSIONS_1, client)

    # Query by role
    expected_by_role = {
        'viewer': [
            (u'r/res1', set([u'group/g1'])),
            (u'r/res2', set([u'group/g1'])),
            (u'r/res3', set([u'group/g1', u'group/g3'])),
        ],
        'admin': [
            (u'r/res1', set([u'user/u1'])),
            (u'r/res4', set([u'group/g2'])),
        ],
        'writer': [(u'r/res3', set([u'group/g3'])),],
    }

    for role, access in expected_by_role.iteritems():
      result = [r for r in (
          data_access.query_access_by_permission(session, role))]
      for item in result:
        _, acc_res, acc_members = item
        if not (acc_res, acc_members) in access:
            LOGGER.warn('(%s, %s), %s', acc_res, acc_members, access)
        self.assertIn((acc_res, acc_members), access,
                      'Should find access in expected')

    # Query by permission
    expected_by_permission = {
        'readonly': [
            (u'r/res1', set([u'group/g1'])),
            (u'r/res2', set([u'group/g1'])),
            (u'r/res3', set([u'group/g1', u'group/g3'])),
        ],
        'delete': [
            (u'r/res1', set([u'user/u1'])),
            (u'r/res4', set([u'group/g2'])),
        ],
        'writeonly': [(u'r/res3', set([u'group/g3'])),],
    }

    for perm, access in expected_by_permission.iteritems():
      result = [r for r in (
          data_access.query_access_by_permission(session,
                                                 permission_name=perm))]
      for item in result:
        _, acc_res, acc_members = item
        if not (acc_res, acc_members) in access:
            LOGGER.warn('(%s, %s), %s', acc_res, acc_members, access)
        self.assertIn((acc_res, acc_members), access,
                      'Should find access in expected')

    # Test the source expansion
    expected_by_permission = {
        'delete': [
            (u'r/res1', set([u'user/u1'])),
            (u'r/res2', set([u'user/u1'])),
            (u'r/res3', set([u'user/u1'])),
            (u'r/res4', set([u'user/u1', u'group/g2'])),
        ],
    }

    for perm, access in expected_by_permission.iteritems():
      result = [r for r in (
          data_access.query_access_by_permission(session,
                                                 permission_name=perm,
                                                 expand_resources=True))]
      for item in result:
        _, acc_res, acc_members = item
        if not (acc_res, acc_members) in access:
            LOGGER.warn('(%s, %s), %s', acc_res, acc_members, access)
        self.assertIn((acc_res, acc_members), access,
                      'Should find access in expected')

    # Test the group expansion
    expected_by_permission = {
        'delete': [
            (u'r/res1', set([u'user/u1'])),
            (u'r/res4', set([u'user/u3', u'user/u4', u'group/g2'])),
        ],
    }

    for perm, access in expected_by_permission.iteritems():
      result = [r for r in (
          data_access.query_access_by_permission(
              session,
              permission_name=perm,
              expand_groups=True,
              expand_resources=False))]

      for item in result:
        _, acc_res, acc_members = item
        self.assertIn((acc_res, acc_members), access,
                      'Should find access in expected')

  def test_query_access_by_member(self):
    """Test query_access_by_member."""
    session_maker, data_access = session_creator('test')
    session = session_maker()
    client = ModelCreatorClient(session, data_access)
    _ = ModelCreator(test_models.DENORMALIZATION_TESTING_1, client)

    checks = [
        ('user/u1', [u'a'], False, {u'r/res3', u'r/res1'}),
        ('user/u2', [u'a'], False, {u'r/res2'}),
        ('user/g2g1u1', [u'a'], False, {u'r/res3'}),
        ('user/g2u1', [u'a'], False, {u'r/res3'}),
        ('user/u1', [u'a'], True, {u'r/res1', u'r/res2', u'r/res3'}),
        ('user/u1', [u'b'], True, {u'r/res2', u'r/res3'}),
    ]

    for user, permissions, expansion, expected_result in checks:
      result = data_access.query_access_by_member(session,
                                                  user,
                                                  permissions,
                                                  expansion)
      mapping = defaultdict(set)
      for role, resources in result:
        for resource in resources:
          mapping[role].add(resource)
      self.assertEqual(expected_result, mapping[permissions[0]])

  def test_query_access_by_resource(self):
    """Test query_access_by_resource."""
    session_maker, data_access = session_creator('test')
    session = session_maker()
    client = ModelCreatorClient(session, data_access)
    _ = ModelCreator(test_models.DENORMALIZATION_TESTING_1, client)

    checks = [
        ('r/res1', ['a'], False, [u'group/g1',
                                  u'user/u1']),

        ('r/res2', ['a'], False, [u'group/g1',
                                  u'user/u1',
                                  u'user/u2']),

        ('r/res3', ['a'], False, [u'group/g1',
                                  u'user/u1',
                                  u'user/u2',
                                  u'group/g2']),

        ('r/res3', ['a'], True, [u'group/g1',
                                 u'user/u1',
                                 u'user/u2',
                                 u'group/g2',
                                 u'user/g2u1',
                                 u'group/g2g1',
                                 u'user/g2g1u1'])
    ]

    for resource, permissions, expansion, members in checks:
      res = data_access.query_access_by_resource(
          session,
          resource,
          permission_names=permissions,
          expand_groups=expansion)
      self.assertEqual(set(members), set(res[permissions[0]]))

  def test_query_permissions_by_roles(self):
    """Test query_permissions_by_roles."""
    session_maker, data_access = session_creator('test')
    session = session_maker()
    client = ModelCreatorClient(session, data_access)
    _ = ModelCreator(test_models.ROLES_PERMISSIONS_TESTING_1, client)

    prefix_checks = [
        ([''], ['a', 'b', 'c', 'd', 'e', 'f']),
        (['f'], ['a']),
    ]
    name_checks = [
        (['h', 'g'], ['a', 'c', 'e', 'b', 'd', 'f']),
        (['f'], ['a']),
        (['e'], ['a', 'b']),
        (['d', 'e'], ['a', 'b', 'c']),
    ]

    for prefixes, expectations in prefix_checks:
      res = data_access.query_permissions_by_roles(
          session,
          role_names=[],
          role_prefixes=prefixes)
      mapping = defaultdict(set)
      all_set = set()
      for role, permission in res:
        mapping[role.name].add(permission.name)
        all_set.add(permission.name)
      self.assertEqual(set(expectations), all_set)

    for names, expectations in name_checks:
      res = data_access.query_permissions_by_roles(
          session,
          role_names=names,
          role_prefixes=[])
      mapping = defaultdict(set)
      all_set = set()
      for role, permission in res:
        mapping[role.name].add(permission.name)
        all_set.add(permission.name)
      self.assertEqual(set(expectations), all_set)

  def test_set_iam_policy(self):
    """Test check_iam_policy."""
    session_maker, data_access = session_creator('test', None, None, False)
    session = session_maker()
    client = ModelCreatorClient(session, data_access)
    _ = ModelCreator(test_models.EXPLAIN_GRANTED_1, client)

    set_policy = data_access.set_iam_policy
    get_policy = data_access.get_iam_policy

    callable = lambda: set_policy(session, 'r/res1', {
            'bindings' : {}, 'etag': 'somehash',
        })
    self.assertRaises(Exception, callable)

    policy = get_policy(session, 'r/res1')
    self.assertNotEqual(set([u'user/u1', u'group/g2']),
                        set(policy['bindings']['viewer']))

    policy = get_policy(session, 'r/res1')
    policy['bindings']['viewer'] = ['user/u1', 'group/g2']
    set_policy(session, 'r/res1', policy)

    policy = get_policy(session, 'r/res1')
    self.assertEqual(set([u'user/u1', u'group/g2']),
                     set(policy['bindings']['viewer']))

    resource = 'r/res4'
    policy = get_policy(session, resource)
    self.assertEqual(set([u'group/g2']),
                     set(policy['bindings']['admin']))
    policy['bindings']['writer'] = ['user/u3', 'user/u4']
    set_policy(session, resource, policy)
    policy = get_policy(session, resource)
    self.assertEqual(set([u'user/u3', u'user/u4']),
                     set(policy['bindings']['writer']))

  def test_get_iam_policy(self):
    """Test check_iam_policy."""
    session_maker, data_access = session_creator('test', None, None, False)
    session = session_maker()
    client = ModelCreatorClient(session, data_access)
    _ = ModelCreator(test_models.EXPLAIN_GRANTED_1, client)

    checks = (
        ('r/res1', {
            u'viewer': [u'group/g1'],
            u'admin': [u'user/u1'],
        }),
        ('r/res2', {
            u'viewer': [u'group/g1'],
        }),
        ('r/res3', {
            u'viewer': [u'group/g1'],
            u'writer': [u'group/g3'],
        }),
        ('r/res4', {
            u'admin': [u'group/g2'],
        })
    )

    f = data_access.get_iam_policy
    for resource, policy_expected in checks:
      res = f(session, resource)
      self.assertEqual(policy_expected, res['bindings'])
      self.assertIn('etag', res, 'Etag must be in policy')
      self.assertEqual(resource, res['resource'])

  def test_get_iam_policy_by_role(self):
    """Test check_iam_policy."""
    session_maker, data_access = session_creator('test', None, None, False)
    session = session_maker()
    client = ModelCreatorClient(session, data_access)
    _ = ModelCreator(test_models.EXPLAIN_GRANTED_1, client)
    expected_bindings = {u'viewer': [u'group/g1']}
    iam_policy = data_access.get_iam_policy(session, 'r/res1',
                                            roles=['viewer', 'writer'])
    self.assertEqual(expected_bindings, iam_policy['bindings'])

  def test_check_iam_policy(self):
    """Test check_iam_policy."""
    session_maker, data_access = session_creator('test', None, None, False)
    session = session_maker()
    client = ModelCreatorClient(session, data_access)
    _ = ModelCreator(test_models.EXPLAIN_GRANTED_1, client)

    checks = [
        ('r/res1', 'read', 'user/u1', True),
        ('r/res1', 'list', 'user/u1', True),
        ('r/res1', 'write', 'user/u1', True),
        ('r/res1', 'delete', 'user/u1', True),

        ('r/res1', 'read', 'user/u3', True),
        ('r/res1', 'list', 'user/u3', True),
        ('r/res1', 'write', 'user/u3', False),
        ('r/res1', 'delete', 'user/u3', False),

        ('r/res4', 'read', 'user/u3', True),
        ('r/res4', 'list', 'user/u3', True),
        ('r/res4', 'write', 'user/u3', True),
        ('r/res4', 'delete', 'user/u3', True),

        ('r/res3', 'read', 'user/u4', True),
        ('r/res3', 'list', 'user/u4', True),
        ('r/res3', 'write', 'user/u4', True),
        ('r/res3', 'delete', 'user/u4', False),

        ('r/res2', 'read', 'user/u4', False),
        ('r/res2', 'list', 'user/u4', False),
        ('r/res2', 'write', 'user/u4', False),
        ('r/res2', 'delete', 'user/u4', False),
    ]

    f = data_access.check_iam_policy
    for frn, perm, member, expectation in checks:
      if expectation:
        self.assertTrue(f(session, frn, perm, member))
      else:
        self.assertFalse(f(session, frn, perm, member))

  def test_get_roles_by_permission_names(self):
    session_maker, data_access = session_creator('test')
    session = session_maker()
    client = ModelCreatorClient(session, data_access)
    _ = ModelCreator(test_models.ROLES_PERMISSIONS_TESTING_1, client)

    tests = [
        ({'a'}, {'a', 'b', 'c', 'd', 'e', 'f', 'g'}),
        ({'a', 'b'}, {'a', 'b', 'c', 'd', 'e'}),
        ({'a', 'b', 'c'}, {'a', 'b', 'c', 'd'}),
        ({'a', 'c', 'e'}, {'a', 'b', 'g'}),
        ({'b', 'd', 'f'}, {'a', 'h'}),
        ({'a', 'c', 'd'}, {'a', 'b', 'c'}),
        (set(), {'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h'}),
    ]

    for permissions, expected_roles in tests:
      roles = data_access.get_roles_by_permission_names(session, permissions)
      role_names = [str(r.name) for r in roles]
      self.assertEqual(expected_roles, set(role_names))

  def test_add_member(self):
    session_maker, data_access = session_creator('test')
    session = session_maker()
    data_access.add_member(session, 'user/u1')
    data_access.add_member(session, 'user/u2')
    data_access.add_member(session, 'user/u3')
    data_access.add_member(session, 'user/u4')
    data_access.add_member(session, 'group/g1')
    data_access.add_member(session, 'group/g2')
    data_access.add_member(session, 'group/g3')
    data_access.add_member(session, 'group/g4')
    data_access.add_member(session, 'user/u5', ['group/g1', 'group/g2'])
    data_access.add_member(session, 'user/u6',
                           ['group/g1', 'group/g2', 'group/g3'])

    data_access.get_member(session, 'user/u1')
    data_access.get_member(session, 'user/u2')
    data_access.get_member(session, 'user/u3')
    data_access.get_member(session, 'user/u4')
    data_access.get_member(session, 'user/u5')
    data_access.get_member(session, 'user/u6')

    # Find existing users
    self.assertTrue(1 == len(data_access.get_member(session, 'user/u1')))
    self.assertTrue(1 == len(data_access.get_member(session, 'user/u2')))
    self.assertTrue(1 == len(data_access.get_member(session, 'user/u3')))
    self.assertTrue(1 == len(data_access.get_member(session, 'user/u4')))
    self.assertTrue(1 == len(data_access.get_member(session, 'user/u5')))
    self.assertTrue(1 == len(data_access.get_member(session, 'user/u6')))

    # Find existing groups
    self.assertTrue(1 == len(data_access.get_member(session, 'group/g1')))
    self.assertTrue(1 == len(data_access.get_member(session, 'group/g2')))
    self.assertTrue(1 == len(data_access.get_member(session, 'group/g3')))

    # Check names as well
    self.assertEquals('group/g1',
                      data_access.get_member(session, 'group/g1')[0].name)
    self.assertEquals('user/u1',
                      data_access.get_member(session, 'user/u1')[0].name)
    self.assertEquals('user/u6',
                      data_access.get_member(session, 'user/u6')[0].name)

    # Non-existing users should not be found
    self.assertTrue(0 == len(data_access.get_member(session, 'group/g5')))
    self.assertTrue(0 == len(data_access.get_member(session, 'user/u7')))

  def test_resource_ancestors(self):
    session_maker, data_access = session_creator('test')
    session = session_maker()
    client = ModelCreatorClient(session, data_access)
    _ = ModelCreator(test_models.RESOURCE_PATH_TESTING_1, client)

    tests = [
        [u'r/r1',
         u'r/r1r3',
         u'r/r1r3r1',
         u'r/r1r3r1r1'],

        [u'r/r1'],

        [u'r/r1',
         u'r/r1r3',
         u'r/r1r3r1'],

        [u'r/r1',
         u'r/r1r5',
         u'r/r1r6r1',
         u'r/r1r6r1r1',
         u'r/r1r6r1r1r1'],
    ]

    # parent, set(child) relation
    test_resources = [chain[-1] for chain in tests]
    graph = data_access.resource_ancestors(session, test_resources)
    for chain in tests:
      for i in range(0, len(chain)-1):
        parent = chain[i]
        child = chain[i+1]
        self.assertTrue(child in graph[parent])

  def test_find_resource_path(self):
    session_maker, data_access = session_creator('test')
    session = session_maker()
    client = ModelCreatorClient(session, data_access)
    _ = ModelCreator(test_models.RESOURCE_PATH_TESTING_1, client)

    tests = {
        u'r/r1r3r1r1':
            {u'r/r1', u'r/r1r3', u'r/r1r3r1', u'r/r1r3r1r1'},
        u'r/r1':
            {u'r/r1'},
        u'r/r1r3r1':
            {u'r/r1', u'r/r1r3', u'r/r1r3r1'},
        u'r/r1r6r1r1r1':
            {u'r/r1r6r1r1r1', u'r/r1r6r1r1', u'r/r1r6r1',
             u'r/r1r5', u'r/r1'},
    }

    for test_val, comparison in tests.iteritems():
      result = [r.type_name
                for r in data_access.find_resource_path(session, test_val)]
      self.assertEqual(comparison, set(result))

  def test_get_member(self):
    session_maker, data_access = session_creator('test')
    session = session_maker()
    client = ModelCreatorClient(session, data_access)
    _ = ModelCreator(test_models.MEMBER_TESTING_1, client)

    # Find existing users
    self.assertTrue(1 == len(data_access.get_member(session, 'user/g1g1u1')))
    self.assertTrue(1 == len(data_access.get_member(session, 'user/g2u1')))
    self.assertTrue(1 == len(data_access.get_member(session, 'user/g2u2')))
    self.assertTrue(1 == len(data_access.get_member(session, 'user/g2u3')))
    self.assertTrue(1 == len(data_access.get_member(session, 'user/g3u1')))
    self.assertTrue(1 == len(data_access.get_member(session, 'user/g3u2')))
    self.assertTrue(1 == len(data_access.get_member(session, 'user/g3u3')))
    self.assertTrue(1 == len(data_access.get_member(session, 'user/g3g1u1')))
    self.assertTrue(1 == len(data_access.get_member(session, 'user/g3g1u2')))
    self.assertTrue(1 == len(data_access.get_member(session, 'user/g3g1u3')))

    # Find existing groups
    self.assertTrue(1 == len(data_access.get_member(session, 'group/g1')))
    self.assertTrue(1 == len(data_access.get_member(session, 'group/g2')))
    self.assertTrue(1 == len(data_access.get_member(session, 'group/g3')))
    self.assertTrue(1 == len(data_access.get_member(session, 'group/g1g1')))
    self.assertTrue(1 == len(data_access.get_member(session, 'group/g3g1')))

    # Check names as well
    self.assertEquals('group/g1',
                      data_access.get_member(session, 'group/g1')[0].name)
    self.assertEquals('user/g3g1u2',
                      data_access.get_member(session, 'user/g3g1u2')[0].name)
    self.assertEquals('user/g2u3',
                      data_access.get_member(session, 'user/g2u3')[0].name)

    # Non-existing users should not be found
    self.assertTrue(0 == len(data_access.get_member(session, 'group/g4')))
    self.assertTrue(0 == len(data_access.get_member(session, 'user/u5')))

  def test_expand_resources_1(self):
    session_maker, data_access = session_creator('test')
    session = session_maker()
    client = ModelCreatorClient(session, data_access)
    _ = ModelCreator(test_models.RESOURCE_EXPANSION_1, client)

    self.assertEqual(
        set(['res{}'.format(i) for i in range(1, 9)]),
        set([r.name for r in session.query(data_access.TBL_RESOURCE).all()]),
        'Expecting all resources to be added to the database')

    def expand(resource):
        return [
            '/'.join(i.full_name.split('/')[-3:-1])
            for i in data_access.expand_resources_by_type_names(session, [resource]).values()[0]
        ]

    self.assertEqual(set(expand('r/res1')),
                     set([u'r/res{}'.format(i) for i in range(1, 9)]),
                     'Expecting expansion of res1 to comprise all resources')
    self.assertEqual(set(expand('r/res2')),
                     set([u'r/res2']),
                     'Expecting expansion of res2 to comprise res2')
    self.assertEqual(set(expand('r/res3')),
                     set([u'r/res3']),
                     'Expecting expansion of res3 to comprise res3')
    self.assertEqual(set(expand('r/res4')),
                     set([u'r/res4']),
                     'Expecting expansion of res4 to comprise res4')
    self.assertEqual(set(expand('r/res5')),
                     set([u'r/res5', u'r/res6', u'r/res7', u'r/res8']),
                     'Expecting expansion of res5 to comprise res{5,6,7,8}')
    self.assertEqual(set(expand('r/res5')),
                     set([u'r/res5', u'r/res6', u'r/res7', u'r/res8']),
                     'Expecting expansion of res5 to comprise res{5,6,7,8}')
    self.assertEqual(set(expand('r/res6')),
                     set([u'r/res6', u'r/res7', u'r/res8']),
                     'Expecting expansion of res6 to comprise res{6,7,8}')
    self.assertEqual(set(expand('r/res7')),
                     set([u'r/res7']),
                     'Expecting expansion of res7 to comprise res7')
    self.assertEqual(set(expand('r/res8')),
                     set([u'r/res8']),
                     'Expecting expansion of res8 to comprise res8')

  def test_expand_resources_2(self):
    """Expand resource tree."""
    session_maker, data_access = session_creator('test')
    session = session_maker()
    client = ModelCreatorClient(session, data_access)
    _ = ModelCreator(test_models.RESOURCE_EXPANSION_2, client)

    self.assertEqual(
        set(['r/res{}'.format(i) for i in range(1, 9)]),
        set(['r/{}'.format(r.name)
             for r in session.query(data_access.TBL_RESOURCE).all()]),
        'Expecting all resources to be added to the database')

    def expand(resource):
        return [
            '/'.join(i.full_name.split('/')[-3:-1])
            for i in data_access.expand_resources_by_type_names(session, [resource]).values()[0]
        ]

    self.assertEqual(
        set(expand('r/res1')),
        set([u'r/res{}'.format(i) for i in range(1, 9)]),
        'Expecting expansion of res1 to comprise all resources')

    self.assertEqual(
        set(expand('r/res2')),
        set([u'r/res{}'.format(i) for i in range(2, 9)]),
        'Expecting expansion of res2 to comprise all resources but res1')

    self.assertEqual(
        set(expand('r/res3')),
        set([u'r/res3', u'r/res4', u'r/res5']),
        'Expecting expansion of res3 to comprise res3,res4 and res5')

    self.assertEqual(
        set(expand('r/res8')),
        set([u'r/res8']),
        'Expecting expansion of res8 to comprise only res8')


if __name__ == '__main__':
  unittest.main()
