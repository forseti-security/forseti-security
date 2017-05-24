import unittest

from google.cloud.security.iam.explain.service import GrpcExplainerFactory
from google.cloud.security.iam.playground.service import GrpcPlaygrounderFactory
from google.cloud.security.iam.dao import ModelManager

from tests.iam.api_tests.api_tester import ModelTestRunner, create_test_engine, cleanup

class TestServiceConfig:
    def __init__(self):
        engine = create_test_engine()
        self.model_manager = ModelManager(engine)

    def run_in_background(self, function):
        function()

model = {
        'resources':{
                'organization/org1' : {
                        'project/project1' : {
                                'bucket/bucket1' : {},
                            },
                        'project/project2' : {
                                'bucket/bucket2' : {},
                                'vm/instance-1' : {},
                            },
                    },
            },
        'memberships':{
                'group/a' : {
                        'user/a' : {},
                        'user/b' : {},
                        'user/c' : {},
                        'group/b' : {
                                'user/a' : {},
                                'user/d' : {},
                            },
                    },
                'user/e' : {},
            },
        'roles':{
                'a' : ['a','b','c','d','e'],
                'b' : ['a','b','c'],
                'c' : ['f','g','h'],
                'd' : ['f','g','i']
            },
        'bindings':{
                'organization/org1' : {
                        'b': ['group/a'],
                    },
                'project/project2' : {
                        'a': ['group/b'],
                    },
                'vm/instance-1' : {
                        'a': ['user/a'],
                    },
            },
    }

def create_tester():
    return ModelTestRunner(model,
                           TestServiceConfig(),\
                     [\
                      GrpcExplainerFactory,\
                      GrpcPlaygrounderFactory,\
                      ])

class ModelTest(unittest.TestCase):

    def setUp(self):
        self.setup = create_tester()

    def test_check_policy(self):

        def test(client):
            self.assertTrue(client.playground.check_iam_policy('organization/org1/project/project2/vm/instance-1', 'c', 'user/d').result)
            self.assertTrue(client.playground.check_iam_policy('organization/org1/project/project2/vm/instance-1', 'e', 'user/d').result)
            self.assertTrue(client.playground.check_iam_policy('organization/org1/project/project2/vm/instance-1', 'e', 'user/a').result)

            self.assertFalse(client.playground.check_iam_policy('organization/org1', 'e', 'user/a').result)
            self.assertFalse(client.playground.check_iam_policy('organization/org1/project/project2', 'e', 'user/c').result)
            self.assertFalse(client.playground.check_iam_policy('organization/org1/project/project2/vm/instance-1', 'e', 'user/c').result)

        self.setup.run(test)

    def test_query_role_permissions(self):
        def test(client):
            response = client.explain.query_permissions_by_roles(role_names=['a','b'])
            self.assertTrue(len(response.permissionsbyroles) == 2)
            for mapping in response.permissionsbyroles:
                if mapping.role == 'a':
                    self.assertEquals(set(mapping.permissions), set(['a','b','c','d','e']))
                elif mapping.role == 'b':
                    self.assertEquals(set(mapping.permissions), set(['a','b','c']))
                else:
                    self.assertFalse(True)
        self.setup.run(test)
        
    def test_query_access_by_resources(self):
        def test(client):
            response = client.explain.query_access_by_resources(resource_name='organization/org1/project/project2', permission_names=['a','c'], expand_groups=True)
            self.assertTrue(len(response.accesses) == 2)
            for access in response.accesses:
                if access.role == 'a':
                    self.assertEqual(set(access.members), set(['group/b', 'user/a', 'user/d']))
                elif access.role == 'b':
                    self.assertEqual(set(access.members), set(['group/a', 'user/a', 'user/b', 'user/c', 'user/d', 'group/b']))
                else:
                    self.assertFalse(True, 'Should never get here')
        self.setup.run(test)

    def test_query_access_by_members(self):
        def test(client):
            response = client.explain.query_access_by_members('group/a', 'a', expand_resources=True)
            for access in response.accesses:
                if access.role == 'b':
                    self.assertEqual(set(access.resources),
                                     set([
                                         'bucket/bucket1',
                                         'project/project1',
                                         'vm/instance-1',
                                         'bucket/bucket2',
                                         'project/project2',
                                         'organization/org1',
                                         ]))
                else:
                    self.assertFalse(True, 'Should never get here')
        self.setup.run(test)

    def test_explain_granted(self):
        def test(client):
            response = client.explain.explain_granted(member_name='user/d', resource_name='organization/org1/project/project2/bucket/bucket2', role='b')
            self.assertTrue(response, 'Expected to get a grant explanation')
        self.setup.run(test)

    def test_explain_denied(self):
        def test(client):
            response = client.explain.explain_denied(member_name='user/d', resource_names=['organization/org1/project/project2/bucket/bucket2'], permission_names=['f','i'])
            self.assertTrue(response, 'Expected to get a deny explanation')
            
            response = client.explain.explain_denied(member_name='user/e', resource_names=['organization/org1/project/project2/bucket/bucket2'], permission_names=['a'])
            self.assertTrue(response, 'Expected to get a deny explanation')
        self.setup.run(test)
