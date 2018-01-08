# Copyright 2017 The Forseti Security Authors. All rights reserved.
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

from google.cloud.forseti.services.playground import playground_pb2
from google.cloud.forseti.services.playground import playground_pb2_grpc
from google.cloud.forseti.services.playground import playgrounder


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

    def ping(self, request, _):
        """ping implemented to check service availability."""

        return playground_pb2.PingReply(data=request.data)

    def set_iam_policy(self, request, context):
        """Sets the policy for a resource."""

        handle = self._get_handle(context)
        policy = {'etag': request.policy.etag, 'bindings': {}}
        for binding in request.policy.bindings:
            policy['bindings'][binding.role] = binding.members

        self.playgrounder.set_iam_policy(handle,
                                         request.resource,
                                         policy)

        return playground_pb2.SetIamPolicyReply()

    def get_iam_policy(self, request, context):
        """Gets the policy for a resource."""

        handle = self._get_handle(context)
        policy = self.playgrounder.get_iam_policy(handle,
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

    def check_iam_policy(self, request, context):
        """Checks access according to policy to a specified resource."""

        handle = self._get_handle(context)
        authorized = self.playgrounder.check_iam_policy(handle,
                                                        request.resource,
                                                        request.permission,
                                                        request.identity)
        reply = playground_pb2.CheckIamPolicyReply()
        reply.result = authorized
        return reply

    def add_group_member(self, request, context):
        """Adds a member to the model."""

        handle = self._get_handle(context)
        self.playgrounder.add_group_member(handle,
                                           request.member_type_name,
                                           request.parent_type_names)
        return playground_pb2.AddGroupMemberReply()

    def delete_group_member(self, request, context):
        """Deletes a member from the model."""

        handle = self._get_handle(context)
        self.playgrounder.delete_group_member(handle,
                                              request.member_name,
                                              request.parent_name,
                                              request.only_delete_relationship)
        return playground_pb2.DelGroupMemberReply()

    def list_group_members(self, request, context):
        """Lists members in the model."""

        handle = self._get_handle(context)
        member_names = self.playgrounder.list_group_members(handle,
                                                            request.prefix)
        reply = playground_pb2.ListGroupMembersReply()
        reply.member_names.extend(member_names)
        return reply

    def delete_resource(self, request, context):
        """Deletes a resource from the model."""

        handle = self._get_handle(context)
        self.playgrounder.delete_resource(handle,
                                          request.resource_type_name)
        return playground_pb2.DelResourceReply()

    def add_resource(self, request, context):
        """Adds a resource to the model."""

        handle = self._get_handle(context)
        self.playgrounder.add_resource(handle,
                                       request.resource_type_name,
                                       request.parent_type_name,
                                       request.no_require_parent)
        return playground_pb2.AddResourceReply()

    def list_resources(self, request, context):
        """Lists resources in the model."""

        handle = self._get_handle(context)
        resources = self.playgrounder.list_resources(handle,
                                                     request.prefix)
        reply = playground_pb2.ListResourcesReply()
        reply.full_resource_names.extend([r.type_name for r in resources])
        return reply

    def delete_role(self, request, context):
        """Deletes a role within the model."""

        handle = self._get_handle(context)
        self.playgrounder.delete_role(handle,
                                      request.role_name)
        return playground_pb2.DelRoleReply()

    def add_role(self, request, context):
        """Adds a role to the model."""

        handle = self._get_handle(context)
        self.playgrounder.add_role(handle,
                                   request.role_name,
                                   request.permissions)
        return playground_pb2.AddRoleReply()

    def list_roles(self, request, context):
        """List roles from the model."""

        handle = self._get_handle(context)
        role_names = self.playgrounder.list_roles(handle,
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
