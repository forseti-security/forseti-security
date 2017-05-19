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


""" Unit Tests: Database abstraction objects for IAM Explain. """

from google.apputils import basetest
import uuid
import os
from collections import defaultdict
from sqlalchemy.orm.exc import NoResultFound

from google.cloud.security.iam.utils import full_to_type_name
from google.cloud.security.iam.dao import ModelManager, session_creator, create_engine
from google.cloud.security.common.util.threadpool import ThreadPool
from tests.iam.unit_tests.test_models import RESOURCE_EXPANSION_1, RESOURCE_EXPANSION_2,\
    MEMBER_TESTING_1, RESOURCE_PATH_TESTING_1, ROLES_PERMISSIONS_TESTING_1,\
    DENORMALIZATION_TESTING_1, ROLES_PREFIX_TESTING_1, MEMBER_TESTING_2
from tests.iam.unit_tests.model_tester import ModelCreator, ModelCreatorClient

def create_test_engine():
    tmpfile = '/tmp/{}.db'.format(uuid.uuid4())
    return create_engine('sqlite:///{}'.format(tmpfile)), tmpfile

class DaoTest(basetest.TestCase):
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
        _ = ModelCreator(ROLES_PREFIX_TESTING_1, client)

        expectations = {
                '' : {
                    'cloud.admin',
                    'cloud.reader',
                    'cloud.writer',
                    'db.viewer',
                    'db.writer'
                    },
                'cloud' : {
                    'cloud.admin',
                    'cloud.reader',
                    'cloud.writer',
                    },
                'db' : {
                    'db.viewer',
                    'db.writer',
                    },
                'admin' : set(),
            }

        for prefix, expected_roles in expectations.iteritems():
            role_names = data_access.list_roles_by_prefix(session, prefix)
            self.assertEqual(expected_roles, set(role_names))

    def test_add_role_by_name(self):
        """Test add_role_by_name."""
        session_maker, data_access = session_creator('test')
        session = session_maker()
        client = ModelCreatorClient(session, data_access)
        _ = ModelCreator(ROLES_PREFIX_TESTING_1, client)

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

    def test_del_role_by_name(self):
        """Test del_role_by_name."""
        session_maker, data_access = session_creator('test')
        session = session_maker()
        client = ModelCreatorClient(session, data_access)
        _ = ModelCreator(ROLES_PREFIX_TESTING_1, client)

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

        # Delete the new role
        data_access.del_role_by_name(session, u'test_role')

        # Get role by permission to check it's queryable
        res = data_access.get_roles_by_permission_names(session, ['perm1'])
        self.assertEqual(set(), set(res))

    def test_add_group_member(self):
        """Test add_group_member."""
        session_maker, data_access = session_creator('test')
        session = session_maker()
        client = ModelCreatorClient(session, data_access)
        _ = ModelCreator(MEMBER_TESTING_2, client)

        memberships = {
                'user/t1' : ['group/g1'],
                'user/t2' : ['group/g2', 'group/g3'],
                'user/t3' : ['group/g3g2g1', 'group/g3'],
                'group/t4' : ['group/g3g2g1', 'group/g3'],
                'group/t5' : ['group/t4'],
                'user/t6' : ['group/t5','group/t4'],
            }
        
        checks = {
                'user/t1' : ['group/g1'],
                'user/t2' : ['group/g2', 'group/g3'],
                'user/t3' : ['group/g3g2'],
                'group/t5': ['group/g3g2'],
            }

        for member, parents in memberships.iteritems():
            data_access.add_group_member(session, member, parents)

        for member, groups in checks.iteritems():
            res = data_access.reverse_expand_members(session, [member])
            res = [m.name for m in res]
            for group in groups:
                self.assertTrue(group in res)

    def test_del_group_member(self):
        """Test del_group_member."""
        session_maker, data_access = session_creator('test')
        session = session_maker()
        client = ModelCreatorClient(session, data_access)
        _ = ModelCreator(MEMBER_TESTING_2, client)

        # Check that the ancestor relationship is existing
        ancestors = data_access.reverse_expand_members(session, ['group/g3g2g1'])
        ancestors = [m.name for m in ancestors]
        for group in ['group/g3', 'group/g3g2', 'group/g2']:
            self.assertTrue(group in ancestors)

        # Delete membership with group/g3g2
        data_access.del_group_member(session, 'group/g3g2g1', 'group/g3g2', True)

        # Check that the ancestor relationship is existing
        ancestors = data_access.reverse_expand_members(session, ['group/g3g2g1'])
        ancestors = [m.name for m in ancestors]
        for group in ['group/g2']:
            self.assertTrue(group in ancestors)
        for group in ['group/g3', 'group/g3g2']:
            self.assertTrue(group not in ancestors)

        # Delete membership with group/g3g2
        data_access.del_group_member(session, 'group/g3g2g1', 'group/g2', True)
        self.assertTrue(1 == len(data_access.reverse_expand_members(session, ['group/g3g2g1'])))

        # Delete the group
        data_access.del_group_member(session, 'group/g3g2g1', '', False)
        self.assertTrue(0 == len(data_access.reverse_expand_members(session, ['group/g3g2g1'])))

        # Create a new model for immediate group deletion
        session_maker, data_access = session_creator('test')
        session = session_maker()
        client = ModelCreatorClient(session, data_access)
        _ = ModelCreator(MEMBER_TESTING_2, client)
        # Delete the group
        data_access.del_group_member(session, 'group/g3g2g1', '', False)
        self.assertTrue(0 == len(data_access.reverse_expand_members(session, ['group/g3g2g1'])))

    def test_list_group_members(self):
        """Test listing of group members."""
        session_maker, data_access = session_creator('test')
        session = session_maker()
        client = ModelCreatorClient(session, data_access)
        _ = ModelCreator(MEMBER_TESTING_2, client)

        all_member_names = data_access.list_group_members(session, '')
        checks = {u'group/g1',
                  u'group/g2',
                  u'group/g3',
                  u'user/u1',
                  u'user/u2',
                  u'group/g3g2',
                  u'group/g3g2g1'
                  }

        for check in checks:
            self.assertTrue(check in all_member_names)

    def test_list_resources_by_prefix(self):
        """Test listing of resources."""
        session_maker, data_access = session_creator('test')
        session = session_maker()
        client = ModelCreatorClient(session, data_access)
        _ = ModelCreator(RESOURCE_EXPANSION_1, client)

        check_resources = {u'r/res{}'.format(i) for i in range(1,9)}
        full_resource_names = data_access.list_resources_by_prefix(session, '')
        resource_names = ['/'.join(r.split('/')[-2:]) for r in full_resource_names]
        self.assertEqual(check_resources, set(resource_names))

        full_resource_names = data_access.list_resources_by_prefix(session, 'res8')
        resource_names = ['/'.join(r.split('/')[-2:]) for r in full_resource_names]
        self.assertEqual(set([u'r/res8']), set(resource_names))

        full_resource_names = data_access.list_resources_by_prefix(session, 'res89')
        resource_names = ['/'.join(r.split('/')[-2:]) for r in full_resource_names]
        self.assertEqual(set(), set(resource_names))

    def test_del_resource_by_name(self):
        """Test del_resource_by_name."""
        session_maker, data_access = session_creator('test')
        session = session_maker()
        client = ModelCreatorClient(session, data_access)
        _ = ModelCreator(RESOURCE_EXPANSION_1, client)

        self.assertTrue(8 == len(data_access.list_resources_by_prefix(session, '')))
        data_access.del_resource_by_type_name(session, 'r/res8')
        self.assertTrue(7 == len(data_access.list_resources_by_prefix(session, '')))
        data_access.del_resource_by_type_name(session, 'r/res6')
        self.assertTrue(5 == len(data_access.list_resources_by_prefix(session, '')))
        data_access.del_resource_by_type_name(session, 'r/res2')
        self.assertTrue(4 == len(data_access.list_resources_by_prefix(session, '')))
        data_access.del_resource_by_type_name(session, 'r/res1')
        self.assertTrue(0 == len(data_access.list_resources_by_prefix(session, '')))

    def test_add_resource_by_name(self):
        """Test add_resource_by_name."""
        session_maker, data_access = session_creator('test')
        session = session_maker()
        client = ModelCreatorClient(session, data_access)
        _ = ModelCreator(RESOURCE_EXPANSION_1, client)

        data_access.add_resource_by_name(session, 'r/res1/r/res9', False)
        data_access.add_resource_by_name(session, 'r/res1/r/res9/r/res10', False)
        data_access.add_resource_by_name(session, 'r/res1/r/res3/r/res11', False)

        self.assertRaises(NoResultFound,
                          lambda : data_access.add_resource_by_name(
                              session, 'r/res13/r/res14', False))
        self.assertTrue(11 == len(data_access.list_resources_by_prefix(
                                    session, '')))

    def test_reverse_expand_members(self):
        session_maker, data_access = session_creator('test')
        session = session_maker()
        client = ModelCreatorClient(session, data_access)
        _ = ModelCreator(MEMBER_TESTING_2, client)

        members = data_access.reverse_expand_members(session,
                                                     ['group/g2','group/g3'])

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

    def test_expand_members(self):
        session_maker, data_access = session_creator('test')
        session = session_maker()
        client = ModelCreatorClient(session, data_access)
        _ = ModelCreator(MEMBER_TESTING_2, client)

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

    def test_explain_granted(self):
        """Test explain_granted."""
        pass

    def test_explain_denied(self):
        """Test explain_denied."""
        pass

    def test_query_access_by_member(self):
        """Test query_access_by_member."""
        session_maker, data_access = session_creator('test')
        session = session_maker()
        client = ModelCreatorClient(session, data_access)
        _ = ModelCreator(DENORMALIZATION_TESTING_1, client)

        checks = [
                ('user/u1', [u'a'], False, {u'r/res3', u'r/res1'}),
                ('user/u2', [u'a'], False, {u'r/res2'}),
                ('user/g2g1u1', [u'a'], False, {u'r/res3'}),
                ('user/g2u1', [u'a'], False, {u'r/res3'}),
                ('user/u1', [u'a'], True, {u'r/res1',u'r/res2',u'r/res3'}),
                ('user/u1', [u'b'], True, {u'r/res2', u'r/res3'}),
            ]

        for user, permissions, expansion, expected_result in checks:
            res = data_access.query_access_by_member(
                session, user, permissions, expansion)
            mapping = defaultdict(set)
            for role, resources in res:
                for resource in resources:
                    mapping[role].add(full_to_type_name(resource))
            self.assertEqual(expected_result, mapping[permissions[0]])

    def test_query_access_by_resource(self):
        """Test query_access_by_resource."""
        session_maker, data_access = session_creator('test')
        session = session_maker()
        client = ModelCreatorClient(session, data_access)
        _ = ModelCreator(DENORMALIZATION_TESTING_1, client)

        checks = [
                ('r/res1', ['a'], False, [u'group/g1',
                                          u'user/u1']),
                ('r/res1/r/res2', ['a'], False, [u'group/g1',
                                                 u'user/u1',
                                                 u'user/u2']),
                ('r/res1/r/res2/r/res3', ['a'], False, [u'group/g1',
                                                        u'user/u1',
                                                        u'user/u2',
                                                        u'group/g2']),
                ('r/res1/r/res2/r/res3', ['a'], True, [u'group/g1',
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
        pass

    def test_set_iam_policy(self):
        pass

    def test_get_iam_policy(self):
        pass

    def test_check_iam_policy(self):
        pass

    def test_denormalize(self):
        return
        session_maker, data_access = session_creator('test')
        session = session_maker()
        client = ModelCreatorClient(session, data_access)
        _ = ModelCreator(DENORMALIZATION_TESTING_1, client)

        denormalization_expected_1 = set([
                ('a', 'r/res3', 'user/u1'),
                ('a', 'r/res3', 'group/g2'),
                ('a', 'r/res3', 'user/g2u1'),
                ('a', 'r/res3', 'group/g2g1'),
                ('a', 'r/res3', 'user/g2g1u1'),

                ('a', 'r/res2', 'user/u2'),
                ('a', 'r/res3', 'user/u2'),

                ('a', 'r/res1', 'group/g1'),
                ('a', 'r/res2', 'group/g1'),
                ('a', 'r/res3', 'group/g1'),
                ('a', 'r/res1', 'user/u1'),
                ('a', 'r/res2', 'user/u1'),
                ('a', 'r/res3', 'user/u1'),
            ])
        
        self.assertTrue(('a','r/res3','user/u1') in denormalization_expected_1)

        for perm, res, member in data_access.denormalize(session):
            triple = (str(perm.name), str(res.full_name), str(member.name))
            triple = (triple[0], '/'.join(triple[1].split('/')[-2:]), triple[2])
            print "Triple: {}".format(triple)
            self.assertTrue(triple in denormalization_expected_1)

    def test_get_roles_by_permission_names(self):
        session_maker, data_access = session_creator('test')
        session = session_maker()
        client = ModelCreatorClient(session, data_access)
        _ = ModelCreator(ROLES_PERMISSIONS_TESTING_1, client)

        tests = [
                ({'a'}, {'a','b','c','d','e','f','g'}),
                ({'a','b'}, {'a','b','c','d','e'}),
                ({'a','b','c'}, {'a','b','c','d'}),
                ({'a','c','e'}, {'a','b','g'}),
                ({'b','d','f'}, {'a','h'}),
                ({'a','c','d'}, {'a','b','c'}),
                (set(), {'a','b','c','d','e','f','g','h'}),
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
        data_access.add_member(session, 'user/u6', ['group/g1', 'group/g2', 'group/g3'])

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
        self.assertEquals('group/g1', data_access.get_member(session, 'group/g1')[0].name)
        self.assertEquals('user/u1', data_access.get_member(session, 'user/u1')[0].name)
        self.assertEquals('user/u6', data_access.get_member(session, 'user/u6')[0].name)

        # Non-existing users should not be found
        self.assertTrue(0 == len(data_access.get_member(session, 'group/g5')))
        self.assertTrue(0 == len(data_access.get_member(session, 'user/u7')))

    def test_resolve_resource_ancestors(self):
        session_maker, data_access = session_creator('test')
        session = session_maker()
        client = ModelCreatorClient(session, data_access)
        _ = ModelCreator(RESOURCE_PATH_TESTING_1, client)

        tests = [
                    [u'r/r1',u'r/r1r3',u'r/r1r3r1',u'r/r1r3r1r1'],
                    [u'r/r1'],
                    [u'r/r1',u'r/r1r3',u'r/r1r3r1'],
                    [u'r/r1', u'r/r1r5', u'r/r1r6r1', u'r/r1r6r1r1', u'r/r1r6r1r1r1'],
            ]

        # parent, set(child) relation
        test_resources = [chain[-1] for chain in tests]
        graph = data_access.resolve_resource_ancestors_by_name(session, test_resources)
        for chain in tests:
            for i in range(0, len(chain)-1):
                parent = unicode('/'.join(chain[:i+1]))
                child  = unicode('/'.join(chain[:i+2]))
                self.assertTrue(child in graph[parent])

    def test_find_resource_path(self):
        session_maker, data_access = session_creator('test')
        session = session_maker()
        client = ModelCreatorClient(session, data_access)
        created_model = ModelCreator(RESOURCE_PATH_TESTING_1, client)

        tests = {
                u'r/r1r3r1r1' :
                    {u'r/r1',u'r/r1r3',u'r/r1r3r1',u'r/r1r3r1r1'},
                u'r/r1' :
                    {u'r/r1'},
                u'r/r1r3r1' :
                    {u'r/r1',u'r/r1r3',u'r/r1r3r1'},
                u'r/r1r6r1r1r1' :
                    {u'r/r1r6r1r1r1', u'r/r1r6r1r1', u'r/r1r6r1',
                     u'r/r1r5',u'r/r1'},
            }

        for test_val, comparison in tests.iteritems():
            result = ['/'.join([r.type, r.name]) for r in data_access.find_resource_path_by_name(session, test_val)]
            self.assertEqual(comparison, set(result))

    def test_get_member(self):
        session_maker, data_access = session_creator('test')
        session = session_maker()
        client = ModelCreatorClient(session, data_access)
        created_model = ModelCreator(MEMBER_TESTING_1, client)

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
        self.assertEquals('group/g1', data_access.get_member(session, 'group/g1')[0].name)
        self.assertEquals('user/g3g1u2', data_access.get_member(session, 'user/g3g1u2')[0].name)
        self.assertEquals('user/g2u3', data_access.get_member(session, 'user/g2u3')[0].name)

        # Non-existing users should not be found
        self.assertTrue(0 == len(data_access.get_member(session, 'group/g4')))
        self.assertTrue(0 == len(data_access.get_member(session, 'user/u5')))

    def test_expand_resources_1(self):
        session_maker, data_access = session_creator('test')
        session = session_maker()
        client = ModelCreatorClient(session, data_access)
        created_model = ModelCreator(RESOURCE_EXPANSION_1, client)

        self.assertEqual(set(['res{}'.format(i) for i in range(1,9)]),
                         set([r.name for r in session.query(data_access.TBL_RESOURCE).all()]),
                         'Expecting all resources to be added to the database')


        def expand(resource):
            return ['/'.join(i.split('/')[-2:]) for i in data_access.expand_resources_by_names(session, [resource])]

        self.assertEqual(set(expand('r/res1')),
                         set([u'r/res{}'.format(i) for i in range(1,9)]),
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
                         set([u'r/res5',u'r/res6',u'r/res7',u'r/res8']),
                         'Expecting expansion of res5 to comprise res{5,6,7,8}')
        self.assertEqual(set(expand('r/res5')),
                         set([u'r/res5',u'r/res6',u'r/res7',u'r/res8']),
                         'Expecting expansion of res5 to comprise res{5,6,7,8}')
        self.assertEqual(set(expand('r/res6')),
                         set([u'r/res6',u'r/res7',u'r/res8']),
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
        created_model = ModelCreator(RESOURCE_EXPANSION_2, client)

        self.assertEqual(set(['r/res{}'.format(i) for i in range(1,9)]),
                         set(['r/{}'.format(r.name) for r in session.query(data_access.TBL_RESOURCE).all()]),
                         'Expecting all resources to be added to the database')

        def expand(resource):
            return ['/'.join(i.split('/')[-2:]) for i in data_access.expand_resources_by_names(session, [resource])]

        self.assertEqual(set(expand('r/res1')),
                         set([u'r/res{}'.format(i) for i in range(1,9)]),
                         'Expecting expansion of res1 to comprise all resources')

        self.assertEqual(set(expand('r/res2')),
                         set([u'r/res{}'.format(i) for i in range(2,9)]),
                         'Expecting expansion of res2 to comprise all resources but res1')

        self.assertEqual(set(expand('r/res3')),
                         set([u'r/res3',u'r/res4',u'r/res5']),
                         'Expecting expansion of res3 to comprise res3,res4 and res5')

        self.assertEqual(set(expand('r/res8')),
                         set([u'r/res8']),
                         'Expecting expansion of res8 to comprise only res8')
