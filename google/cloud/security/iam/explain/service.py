#!/usr/bin/env python

from concurrent import futures
import time
import grpc
from collections import defaultdict

import explain_pb2
import explain_pb2_grpc
import explainer
from google.cloud.security.iam.dao import session_creator

def autoclose_stream(f):
    def wrapper(*args):
        def closed(context):
            return context._state.client == 'closed'
        context = args[-1]
        for result in f(*args):
            if closed(context):
                return
            yield result
    return wrapper

class GrpcExplainer(explain_pb2_grpc.ExplainServicer):
    HANDLE_KEY = "handle"
    
    def _get_handle(self, context):
        metadata = context.invocation_metadata()
        metadata_dict = {}
        for key, value in metadata:
            metadata_dict[key] = value
        return metadata_dict[self.HANDLE_KEY]

    def __init__(self, explainer):
        super(GrpcExplainer, self).__init__()
        self.explainer = explainer

    def Ping(self, request, context):
        return explain_pb2.PingReply(data=request.data)

    def GetAccessByResources(self, request, context):
        model_name = self._get_handle(context)
        mapping = self.explainer.GetAccessByResources(model_name,
                                                      request.resource_name,
                                                      request.permission_names,
                                                      request.expand_groups)
        accesses = []
        for role, members in mapping.iteritems():
            access = explain_pb2.GetAccessByResourcesReply.Access(role=role, resource=request.resource_name, members=members)
            accesses.append(access)

        reply = explain_pb2.GetAccessByResourcesReply()
        reply.accesses.extend(accesses)
        return reply

    def GetAccessByMembers(self, request, context):
        model_name = self._get_handle(context)
        accesses = []
        for role, resources in self.explainer.GetAccessByMembers(model_name,
                                                                 request.member_name,
                                                                 request.permission_names,
                                                                 request.expand_resources):
        
            access = explain_pb2.GetAccessByMembersReply.Access(role=role, resources=resources, member=request.member_name)
            accesses.append(access)
        reply = explain_pb2.GetAccessByMembersReply()
        reply.accesses.extend(accesses)
        return reply

    def GetPermissionsByRoles(self, request, context):
        model_name = self._get_handle(context)
        result = self.explainer.GetPermissionsByRoles(model_name,
                                                      request.role_names,
                                                      request.role_prefixes)

        permissions_by_roles_map = defaultdict(list)
        for role, permission in result:
            permissions_by_roles_map[role.name].append(permission.name)
        
        permissions_by_roles_list = []
        for role, permissions in permissions_by_roles_map.iteritems():
            permissions_by_roles_list.append(explain_pb2.GetPermissionsByRolesReply.PermissionsByRole(role=role, permissions=permissions))
        
        reply = explain_pb2.GetPermissionsByRolesReply()
        reply.permissionsbyroles.extend(permissions_by_roles_list)
        return reply

    def CreateModel(self, request, context):
        handle = self.explainer.CreateModel(request.type)
        
        reply = explain_pb2.CreateModelReply()
        reply.handle = handle
        return reply

    def DeleteModel(self, request, context):
        model_name = request.handle
        self.explainer.DeleteModel(model_name)
        return explain_pb2.DeleteModelReply()

    def ListModel(self, request, context):
        model_names = self.explainer.ListModel()
        reply = explain_pb2.ListModelReply()
        reply.handles.extend(model_names)
        return reply

    #@autoclose_stream
    def Denormalize(self, request, context):
        model_name = self._get_handle(context)
        
        for permission, resource, member in self.explainer.Denormalize(model_name):
            yield explain_pb2.AuthorizationTuple(member=member, permission=permission, resource=resource)

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
        def __init__(self):
            self.session_creator = session_creator('/tmp/explain.db')

        def runInBackground(self, function):
            function()

        def getSession(self):
            return self.session_creator()

    import sys
    serve(endpoint=sys.argv[1] if len(sys.argv) > 1 else '[::]:50051', config=DummyConfig())