
from google.apputils import basetest

from google.cloud.security.iam.explain.service import GrpcExplainerFactory
from google.cloud.security.iam.playground.service import GrpcPlaygrounderFactory
from google.cloud.security.iam.dao import ModelManager

from tests.iam.api_tests.api_tester import ApiTestRunner, create_test_engine


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

    def test_testing(self):
        def test(client):
            print client.list_models()
            self.assertEqual(client.list_models().handles, [], "Models must be empty")
            client.new_model("EMPTY")
            self.assertEqual(len(client.list_models().handles), 1, "One model must be created")
        self.setup.run(test)
