# Copyright 2017 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

""" Playground gRPC service. """

import time
from concurrent import futures
import grpc

from google.cloud.security.iam.playground import playground_pb2
from google.cloud.security.iam.playground import playground_pb2_grpc
from google.cloud.security.iam.playground import playgrounder


# TODO: The next editor must remove this disable and correct issues.
# pylint: disable=missing-type-doc,missing-return-type-doc,missing-return-doc
# pylint: disable=missing-param-doc


# pylint: disable=no-self-use
class GrpcPlaygrounder(playground_pb2_grpc.PlaygroundServicer):
    """Playground gRPC handler."""

    HANDLE_KEY = "handle"
    def _get_handle(self, context):
        """Extract the model handle from the gRPC context."""

        metadata = context.invocation_metadata()
        metadata_dict = {}
        for key, value in metadata:
            metadata_dict[key] = value
        return metadata_dict[self.HANDLE_KEY]

    def __init__(self, playgrounder_api):
        super(GrpcPlaygrounder, self).__init__()
        self.playgrounder = playgrounder_api

    def Ping(self, request, _):
        """Ping implemented to check service availability."""

        return playground_pb2.PingReply(data=request.data)

    def SetIamPolicy(self, request, context):
        """Sets the policy for a resource."""

        handle = self._get_handle(context)
        policy = {'etag': request.policy.etag, 'bindings': {}}
        for binding in request.policy.bindings:
            policy['bindings'][binding.role] = binding.members

        self.playgrounder.SetIamPolicy(handle,
                                       request.resource,
                                       policy)

        return playground_pb2.SetIamPolicyReply()

    def GetIamPolicy(self, request, context):
        """Gets the policy for a resource."""

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
        """Checks access according to policy to a specified resource."""

        handle = self._get_handle(context)
        authorized = self.playgrounder.CheckIamPolicy(handle,
                                                      request.resource,
                                                      request.permission,
                                                      request.identity)
        reply = playground_pb2.CheckIamPolicyReply()
        reply.result = authorized
        return reply

    def AddGroupMember(self, request, context):
        """Adds a member to the model."""

        handle = self._get_handle(context)
        self.playgrounder.AddGroupMember(handle,
                                         request.member_type_name,
                                         request.parent_type_names)
        return playground_pb2.AddGroupMemberReply()

    def DelGroupMember(self, request, context):
        """Deletes a member from the model."""

        handle = self._get_handle(context)
        self.playgrounder.DelGroupMember(handle,
                                         request.member_name,
                                         request.parent_name,
                                         request.only_delete_relationship)
        return playground_pb2.DelGroupMemberReply()

    def ListGroupMembers(self, request, context):
        """Lists members in the model."""

        handle = self._get_handle(context)
        member_names = self.playgrounder.ListGroupMembers(handle,
                                                          request.prefix)
        reply = playground_pb2.ListGroupMembersReply()
        reply.member_names.extend(member_names)
        return reply

    def DelResource(self, request, context):
        """Deletes a resource from the model."""

        handle = self._get_handle(context)
        self.playgrounder.DelResource(handle,
                                      request.full_resource_name)
        return playground_pb2.DelResourceReply()

    def AddResource(self, request, context):
        """Adds a resource to the model."""

        handle = self._get_handle(context)
        self.playgrounder.AddResource(handle,
                                      request.resource_type_name,
                                      request.parent_type_name,
                                      request.no_require_parent)
        return playground_pb2.AddResourceReply()

    def ListResources(self, request, context):
        """Lists resources in the model."""

        handle = self._get_handle(context)
        full_resource_names = self.playgrounder.ListResources(handle,
                                                              request.prefix)
        reply = playground_pb2.ListResourcesReply()
        reply.full_resource_names.extend(full_resource_names)
        return reply

    def DelRole(self, request, context):
        """Deletes a role within the model."""

        handle = self._get_handle(context)
        self.playgrounder.DelRole(handle,
                                  request.role_name)
        return playground_pb2.DelRoleReply()

    def AddRole(self, request, context):
        """Adds a role to the model."""

        handle = self._get_handle(context)
        self.playgrounder.AddRole(handle,
                                  request.role_name,
                                  request.permissions)
        return playground_pb2.AddRoleReply()

    def ListRoles(self, request, context):
        """List roles from the model."""

        handle = self._get_handle(context)
        role_names = self.playgrounder.ListRoles(handle,
                                                 request.prefix)
        reply = playground_pb2.ListRolesReply()
        reply.role_names.extend(role_names)
        return reply


class GrpcPlaygrounderFactory(object):
    """Factory class for Playground service gRPC interface"""

    def __init__(self, config):
        self.config = config

    def create_and_register_service(self, server):
        """Creates a playground service and registers it in the server"""

        service = GrpcPlaygrounder(
            playgrounder_api=playgrounder.Playgrounder(
                self.config))
        playground_pb2_grpc.add_PlaygroundServicer_to_server(service, server)
        return service


def serve(endpoint, config, max_workers=10, wait_shutdown_secs=3):
    """Test function to serve playground service as standalone."""

    server = grpc.server(futures.ThreadPoolExecutor(max_workers))
    GrpcPlaygrounderFactory(config).create_and_register_service(server)
    server.add_insecure_port(endpoint)
    server.start()
    while True:
        try:
            time.sleep(1)
            print "Looping\n"
        except KeyboardInterrupt:
            server.stop(wait_shutdown_secs).wait()
            return


if __name__ == "__main__":
    class DummyConfig(object):
        """Dummy configuration for testing."""

        def run_in_background(self, function):
            """Dummy method, does not run in background."""

            function()

    import sys
    serve(endpoint=sys.argv[1] if len(sys.argv) >
          1 else '[::]:50051', config=DummyConfig())
