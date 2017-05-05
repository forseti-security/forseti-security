import grpc
import uuid
from concurrent import futures
import logging

from google.cloud.security.iam.client import ClientComposition
from google.cloud.security.iam.dao import create_engine

def cleanup(test_callback):
    def wrapper(client):
        for handle in client.list_models().handles:
            client.delete_model(handle)
    return wrapper

def create_test_engine():
    tmpfile = '/tmp/{}.db'.format(uuid.uuid4())
    logging.info('Creating database at {}'.format(tmpfile))
    return create_engine('sqlite:///{}'.format(tmpfile))

class ApiTestRunner(object):
    def __init__(self, service_config, service_factories, port=50058):
        super(ApiTestRunner, self).__init__()
        self.service_config = service_config
        self.service_factories = service_factories
        self.service_port = port

    def run(self, test_callback):
        server = grpc.server(futures.ThreadPoolExecutor(1))
        server.add_insecure_port('[::]:{}'.format(self.service_port))
        for factory in self.service_factories:
            factory(self.service_config).createAndRegisterService(server)
        server.start()
        try:
            client = ClientComposition(endpoint='localhost:{}'.format(self.service_port))
            test_callback(client)
        finally:
            server.stop(0)
