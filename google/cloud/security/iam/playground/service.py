#!/usr/bin/env python

from concurrent import futures
import time
import grpc

import playground_pb2
import playground_pb2_grpc
import playgrounder

class GrpcPlaygrounder(playground_pb2_grpc.PlaygroundServicer):
    HANDLE_KEY = "handle"
    
    def _get_handle(self, context):
        metadata = context.invocation_metadata()
        metadata_dict = {}
        for key, value in metadata:
            metadata_dict[key] = value
        return metadata_dict[self.HANDLE_KEY]

    def __init__(self, playgrounder):
        super(GrpcPlaygrounder, self).__init__()
        self.playgrounder = playgrounder

    def Ping(self, request, context):
        return playground_pb2.PingReply(data=request.data)

    def SetIamPolicy(self, request, context):
        handle = self._get_handle(context)
        policy = {'etag':request.policy.etag, 'bindings':{}}
        for binding in request.policy.bindings:
            policy['bindings'][binding.role] = binding.members
        
        self.playgrounder.SetIamPolicy(handle,
                                       request.resource,
                                       policy)
        
        return playground_pb2.SetIamPolicyReply()


    def GetIamPolicy(self, request, context):
        handle = self._get_handle(context)
        policy = self.playgrounder.GetIamPolicy(handle,
                                                request.resource)

        reply = playground_pb2.GetIamPolicyReply()

        etag = policy['etag']
        bindings = []
        for key, value in policy['bindings'].iteritems():
            binding = playground_pb2.Binding()
            binding.role = key
            binding.members.extend(value)
            bindings.append(binding)

        reply.resource = request.resource
        reply.policy.bindings.extend(bindings)
        reply.policy.etag = etag 
        return reply

    def CheckIamPolicy(self, request, context):
        handle = self._get_handle(context)
        authorized = self.playgrounder.CheckIamPolicy(handle,
                                                      request.resource,
                                                      request.permission,
                                                      request.identity)
        reply = playground_pb2.CheckIamPolicyReply()
        reply.result = authorized;
        return reply

    def AddGroupMember(self, request, context):
        handle = self._get_handle(context)
        self.playgrounder.AddGroupMember(handle,
                                         request.member_name,
                                         request.member_type,
                                         request.parent_names)
        return playground_pb2.AddGroupMemberReply()

    def DelGroupMember(self, request, context):
        handle = self._get_handle(context)
        self.playgrounder.DelGroupMember(handle,
                                         request.member_name,
                                         request.parent_name,
                                         request.only_delete_relationship)
        return playground_pb2.DelGroupMemberReply()

    def ListGroupMembers(self, request, context):
        handle = self._get_handle(context)
        member_names = self.playgrounder.ListGroupMembers(handle,
                                                          request.prefix)
        reply = playground_pb2.ListGroupMembersReply()
        reply.member_names.extend(member_names)
        return reply

    def DelResource(self, request, context):
        handle = self._get_handle(context)
        self.playgrounder.DelResource(handle,
                                      request.full_resource_name)
        return playground_pb2.DelResourceReply()

    def AddResource(self, request, context):
        handle = self._get_handle(context)
        self.playgrounder.AddResource(handle,
                                         request.full_resource_name,
                                         request.resource_type,
                                         request.no_require_parent)
        return playground_pb2.AddResourceReply()

    def ListResources(self, request, context):
        handle = self._get_handle(context)
        full_resource_names = self.playgrounder.ListResources(handle,
                                                              request.prefix)
        reply = playground_pb2.ListResourcesReply()
        reply.full_resource_names.extend(full_resource_names)
        return reply

    def DelRole(self, request, context):
        handle = self._get_handle(context)
        self.playgrounder.DelRole(handle,
                                  request.role_name)
        return playground_pb2.DelRoleReply()

    def AddRole(self, request, context):
        handle = self._get_handle(context)
        self.playgrounder.AddRole(handle,
                                  request.role_name,
                                  request.permissions)
        return playground_pb2.AddRoleReply()

    def ListRoles(self, request, context):
        handle = self._get_handle(context)
        role_names = self.playgrounder.ListRoles(handle,
                                                 request.prefix)
        reply = playground_pb2.ListRolesReply()
        reply.role_names.extend(role_names)
        return reply
    
    

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
