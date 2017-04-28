#!/usr/bin/env python

from concurrent import futures
import time
import grpc

import explain_pb2
import explain_pb2_grpc
import explainer


class GrpcExplainer(explain_pb2_grpc.ExplainServicer):
    
    def __init__(self, explainer):
        super(GrpcExplainer, self).__init__()
        self.explainer = explainer

    def Ping(self, request, context):
        return explain_pb2.PingReply(data=request.data)

    def GetAccessByResources(self, request, context):
        members = self.explainer.GetAccessByResources(request.resource_name,
                                                      request.permission_names,
                                                      request.expand_groups)
        accesses = []
        for member in members:
            access = explain_pb2.GetAccessByResourcesReply.Access()
            access.member = member.name
            access.resource = request.resource_name
            access.role = ""
            accesses.append(access)

        reply = explain_pb2.GetAccessByResourcesReply()
        reply.accesses.extend(accesses)
        return reply

    def GetAccessByMembers(self, request, context):
        raise NotImplementedError()

    def GetPermissionsByRoles(self, request, context):
        raise NotImplementedError()
    
    def CreateModel(self, request, context):
        raise NotImplementedError()
    
    def DeleteModel(self, request, context):
        raise NotImplementedError()
    
    def ListModel(self, request, context):
        raise NotImplementedError()
    
    

class GrpcExplainerFactory:
    def __init__(self, config):
        self.config = config
    
    def createAndRegisterService(self, server):
        service = GrpcExplainer(explainer=explainer.Explainer(self.config))
        explain_pb2_grpc.add_ExplainServicer_to_server(service, server)
        return service

def serve(endpoint, config, max_workers=10, wait_shutdown_secs=3):
    server = grpc.server(futures.ThreadPoolExecutor(max_workers))
    GrpcExplainerFactory(config).createAndRegisterService(server)
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