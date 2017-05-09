from google.apputils import basetest

from google.cloud.security.iam.explain.service import GrpcExplainerFactory
from google.cloud.security.iam.playground.service import GrpcPlaygrounderFactory
from google.cloud.security.iam.dao import ModelManager

from tests.iam.api_tests.api_tester import ModelTestRunner, create_test_engine, cleanup

class TestServiceConfig:
    def __init__(self):
        engine = create_test_engine()
        self.model_manager = ModelManager(engine)

    def runInBackground(self, function):
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
            },
        'roles':{
                'a' : ['a','b','c','d','e'],
                'b' : ['a','b','c'],
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

class ModelTest(basetest.TestCase):

    def setUp(self):
        self.setup = create_tester()
        

    def test_check_model_subset_roles(self):
        
        def test(client):
            self.assertTrue(client.playground.check_iam_policy('organization/org1/project/project2/vm/instance-1', 'c', 'user/d').result)
            self.assertTrue(client.playground.check_iam_policy('organization/org1/project/project2/vm/instance-1', 'e', 'user/d').result)
            self.assertTrue(client.playground.check_iam_policy('organization/org1/project/project2/vm/instance-1', 'e', 'user/a').result)
           
            self.assertFalse(client.playground.check_iam_policy('organization/org1', 'e', 'user/a').result)
            self.assertFalse(client.playground.check_iam_policy('organization/org1/project/project2', 'e', 'user/c').result)
            self.assertFalse(client.playground.check_iam_policy('organization/org1/project/project2/vm/instance-1', 'e', 'user/c').result)

        
        self.setup.run(test)
