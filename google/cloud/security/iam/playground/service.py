#!/usr/bin/env python

from concurrent import futures
import time
import grpc

import playground_pb2
import playground_pb2_grpc
import playgrounder

class GrpcPlaygrounder(playground_pb2_grpc.PlaygroundServicer):
    def __init__(self, playgrounder):
        super(GrpcPlaygrounder, self).__init__()
        self.playgrounder = playgrounder
    
    def Ping(self, request, context):
        return playground_pb2.PingReply(data=request.data)

    def SetIamPolicy(self, request, context):
        return self.playgrounder.SetIamPolicy(request)

    def GetIamPolicy(self, request, context):
        return self.playgrounder.GetIamPolicy(request)

    def CheckIamPolicy(self, request, context):
        return self.playgrounder.CheckIamPolicy(request)

class GrpcPlaygrounderFactory:
    def __init__(self, config):
        self.config = config
    
    def createAndRegisterService(self, server):
        service = GrpcPlaygrounder(playgrounder=playgrounder.Playgrounder(self.config))
        playground_pb2_grpc.add_PlaygroundServicer_to_server(service, server)
        return service

def serve(endpoint, config, max_workers=10, wait_shutdown_secs=3):
    server = grpc.server(futures.ThreadPoolExecutor(max_workers))
    GrpcPlaygrounderFactory(config).createAndRegisterService(server)
    server.add_insecure_port(endpoint)
    server.start()
    while True:
        try:
            time.sleep(1); print "Looping\n"
        except KeyboardInterrupt:
            server.stop(wait_shutdown_secs).wait()
            return

if __name__ == "__main__":
    class DummyConfig:
        def runInBackground(self, function):
            function()

    import sys
    serve(endpoint=sys.argv[1] if len(sys.argv) > 1 else '[::]:50051', config=DummyConfig())
