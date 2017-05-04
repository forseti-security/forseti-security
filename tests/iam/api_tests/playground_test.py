
from google.apputils import basetest

class TestServiceConfig:
    def __init__(self):
        engine = dao.create_engine('sqlite:///:memory:')
        self.model_manager = ModelManager(engine)

    def runInBackground(self, function):
        function()
        
def create_tester():
    return ApiTester(TestServiceConfig(),\
                     [\
                      explain.service.GrpcExplainerFactory,\
                      playground.service.GrpcPlaygroundFactory,\
                      ])

class ApiTest(basetest.TestCase):

    def setUp(self):
        self.setup = create_tester()

    def test_testing(self):
        def test(client):
            print client.list_models()
        self.setup.run(test)
