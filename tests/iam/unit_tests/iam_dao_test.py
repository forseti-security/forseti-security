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

from google.cloud.security.iam.dao import ModelManager, session_creator, create_engine
from google.cloud.security.common.util.threadpool import ThreadPool
from tests.iam.unit_tests.test_models import RESOURCE_EXPANSION_1, RESOURCE_EXPANSION_2,\
    MEMBER_TESTING_1, RESOURCE_PATH_TESTING_1, ROLES_PERMISSIONS_TESTING_1
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

    def test_explain_granted(self):
        """Test explain_granted."""
        pass

    def test_explain_denied(self):
        """Test explain_denied."""
        pass

    def test_query_access_by_member(self):
        pass

    def test_query_access_by_resource(self):
        pass

    def test_query_permissions_by_roles(self):
        pass

    def test_set_iam_policy(self):
        pass

    def test_get_iam_policy(self):
        pass

    def test_check_iam_policy(self):
        pass

    def test_denormalize(self):
        pass

    def test_list_roles_by_prefix(self):
        pass

    def test_add_role_by_name(self):
        pass

    def test_del_role_by_name(self):
        pass

    def test_add_group_member(self):
        pass

    def test_del_group_member(self):
        pass

    def test_list_group_members(self):
        pass

    def test_list_resources_by_prefix(self):
        pass

    def test_del_resource_by_name(self):
        pass

    def test_add_resource_by_name(self):
        pass

    def test_add_resource(self):
        pass

    def test_add_role(self):
        pass

    def test_add_permission(self):
        pass

    def test_add_binding(self):
        pass

    def test_reverse_expand_members(self):
        pass

    def test_expand_members(self):
        pass

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
