import grpc

class ApiTestRunner(object):
    def __init__(self, service_config, service_factories, port=50058):
        super(ApiTester, self).__init__()
        self.service_config = service_config
        self.service_factories = service_factories
        self.service_port = port

    def run(self, test_callback):
        server = grpc.server(futures.ThreadPoolExecutor(1))
        server.add_insecure_port('[::]:{}'.format(self.service_port))
        server.start()
        try:
            client = ClientComposition(endpoint='localhost:{}'.format(self.service_port))
            test_callback(client)
        finally:
            server.stop()
