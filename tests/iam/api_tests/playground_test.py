
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
        self.hasNModels(client, 0)
    
    def hasNModels(self, client, n):
        return len(client.list_models().handles) == n

    def test_create_empty_model(self):
        
        @cleanup
        def test(client):
            
            self.assertEqual(client.list_models().handles, [], 'Excpect no previous models')
            client.new_model("EMPTY")
            self.assertTrue(self.hasNModels(client, 1), 'One model must be created')

        self.setup.run(test)

    def test_create_empty_model_and_delete(self):
        
        @cleanup
        def test(client):
            
            self.assertTrue(self.hasNoModels(client), 'Expect no previous models')
            model = client.new_model("EMPTY")
            self.assertTrue(self.hasNModels(client, 1), 'One model must be created');
            client.delete_model(model)
            self.assertTrue(self.hasNoModels(client), 'Expect no models left')

        self.setup.run(test)
