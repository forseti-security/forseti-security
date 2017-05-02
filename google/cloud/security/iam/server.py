#!/usr/bin/env python

from multiprocessing.pool import ThreadPool
from concurrent import futures
import time
import grpc

from dao import ModelManager, create_engine
from explain.service import GrpcExplainerFactory
from playground.service import GrpcPlaygrounderFactory

static_service_mapping = {
    'explain':GrpcExplainerFactory,
    'playground':GrpcPlaygrounderFactory,
}

class ServiceConfig:
    def __init__(self):
        self.threadPool = ThreadPool()
        
        engine = create_engine('sqlite:///%s'%'/tmp/explain.db')
        self.model_manager = ModelManager(engine)
    
    def runInBackground(self, function):
        function()
        #self.threadPool.apply_async(function)

def serve(endpoint, services, max_workers=1, wait_shutdown_secs=3):

    factories = []
    for service in services:
        factories.append(static_service_mapping[service])

    if not factories:
        raise Exception("No services to start")
    
    config = ServiceConfig()
    server = grpc.server(futures.ThreadPoolExecutor(max_workers))
    for factory in factories:
        factory(config).createAndRegisterService(server)

    server.add_insecure_port(endpoint)
    server.start()
    while True:
        try:
            time.sleep(1)
        except KeyboardInterrupt:
            server.stop(wait_shutdown_secs).wait()
            return

if __name__ == "__main__":
    import sys
    endpoint=sys.argv[1] if len(sys.argv) > 1 else '[::]:50051'
    services=sys.argv[2:] if len(sys.argv) > 2 else []
    serve(endpoint, services)
