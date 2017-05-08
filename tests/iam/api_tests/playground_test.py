
from google.apputils import basetest

from google.cloud.security.iam.explain.service import GrpcExplainerFactory
from google.cloud.security.iam.playground.service import GrpcPlaygrounderFactory
from google.cloud.security.iam.dao import ModelManager

from tests.iam.api_tests.api_tester import ApiTestRunner, create_test_engine, cleanup


class TestServiceConfig:
    def __init__(self):
        engine = create_test_engine()
        self.model_manager = ModelManager(engine)

    def runInBackground(self, function):
        function()
        
def create_tester():
    return ApiTestRunner(TestServiceConfig(),\
                     [\
                      GrpcExplainerFactory,\
                      GrpcPlaygrounderFactory,\
                      ])

class ApiTest(basetest.TestCase):

    def setUp(self):
        self.setup = create_tester()
        
    def hasNoModels(self, client):
        return self.hasNModels(client, 0)
    
    def hasNModels(self, client, n):
        return len(client.list_models().handles) == n

    def test_create_empty_model_and_delete(self):

        def test(client):
            self.assertEquals(client.list_models().handles, [], 'Expect no previous models')
            model1 = client.new_model("EMPTY").handle
            model2 = client.new_model("EMPTY").handle

            self.assertTrue(self.hasNModels(client, 2))
            client.delete_model(model1)
            self.assertTrue(self.hasNModels(client, 1))
            client.delete_model(model2)
            self.assertTrue(self.hasNoModels(client))

        self.setup.run(test)

    def test_create_empty_model(self):
        
        @cleanup
        def test(client):
            self.assertEqual(client.list_models().handles, [], 'Expect no previous models')
            client.new_model("EMPTY")
            self.assertTrue(self.hasNModels(client, 1), 'One model must be created')

        self.setup.run(test)

    def test_create_and_list_members(self):
        
        @cleanup
        def test(client):
            
            model = client.new_model('EMPTY')
            client.switch_model(model.handle)
            self.assertEqual(len(client.playground.list_members("").member_names), 0, 'Expect no members in the empty model');
            client.playground.add_member('user/user1')
            self.assertEqual(len(client.playground.list_members("").member_names), 1, 'Expect one members in the empty model');
            client.playground.add_member('group/group1')
            self.assertEqual(len(client.playground.list_members("").member_names), 2, 'Expect two members in the empty model');
            client.playground.add_member('user/user2', ['group/group1'])
            self.assertEqual(len(client.playground.list_members("").member_names), 3, 'Expect three members in the empty model');
            
            self.assertEqual(len(client.playground.list_members("user").member_names), 2);
            self.assertEqual(len(client.playground.list_members("group").member_names), 1);
            
            client.playground.del_member('user/user1')
            
            self.assertEqual(len(client.playground.list_members("user").member_names), 1);
            self.assertEqual(len(client.playground.list_members("group").member_names), 1);
            
            client.playground.del_member('group/group1')
            client.playground.del_member('user/user2')
            
            self.assertEqual(len(client.playground.list_members("").member_names), 0, 'Expect no members in the empty model');

        self.setup.run(test)