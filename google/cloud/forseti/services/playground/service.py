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

from google.cloud.forseti.services.playground import playground_pb2
from google.cloud.forseti.services.playground import playground_pb2_grpc
from google.cloud.forseti.services.playground import playgrounder
from google.cloud.forseti.common.util import logger

LOGGER = logger.get_logger(__name__)

class GrpcPlaygrounder(playground_pb2_grpc.PlaygroundServicer):
    """Playground gRPC handler."""

    HANDLE_KEY = 'handle'

    def _get_handle(self, context):
        """Extract the model handle from the gRPC context.

        Args:
            context (object): GRPC context

        Returns:
            str: handle of the GRPC call
        """
        metadata = context.invocation_metadata()
        metadata_dict = {}
        for key, value in metadata:
            metadata_dict[key] = value
        return metadata_dict[self.HANDLE_KEY]

    def __init__(self, playgrounder_api):
        """Initialize

        Args:
            playgrounder_api (object): playgrounder library
        """
        super(GrpcPlaygrounder, self).__init__()
        self.playgrounder = playgrounder_api

    def Ping(self, request, _):
        """Ping implemented to check service availability.

        Args:
            request (object): gRPC request
            _ (object): not used

        Returns:
            object: pb2 object of Ping
        """
        LOGGER.debug('request.data = %s', request.data)
        return playground_pb2.PingReply(data=request.data)

    def SetIamPolicy(self, request, context):
        """Sets the policy for a resource.

        Args:
            request (object): gRPC request
            context (object): gRPC context

        Returns:
            object: pb2 object of SetIamPolicy (blank)
        """
        handle = self._get_handle(context)
        policy = {'etag': request.policy.etag, 'bindings': {}}
        for binding in request.policy.bindings:
            policy['bindings'][binding.role] = binding.members

        self.playgrounder.set_iam_policy(handle,
                                         request.resource,
                                         policy)

        return playground_pb2.SetIamPolicyReply()

    def AddGroupMember(self, request, context):
        """Adds a member to the model.

        Args:
            request (object): gRPC request
            context (object): gRPC context

        Returns:
            object: pb2 object of AddGroupMember (blank)
        """
        handle = self._get_handle(context)
        self.playgrounder.add_group_member(handle,
                                           request.member_type_name,
                                           request.parent_type_names)
        return playground_pb2.AddGroupMemberReply()

    def DeleteGroupMember(self, request, context):
        """Deletes a member from the model.

        Args:
            request (object): gRPC request
            context (object): gRPC context

        Returns:
            object: pb2 object of DeleteGroupMember (blank)
        """
        handle = self._get_handle(context)
        self.playgrounder.delete_group_member(handle,
                                              request.member_name,
                                              request.parent_name,
                                              request.only_delete_relationship)
        return playground_pb2.DeleteGroupMemberReply()

    def DeleteRole(self, request, context):
        """Deletes a role within the model.

        Args:
            request (object): gRPC request
            context (object): gRPC context

        Returns:
            object: pb2 object of DeleteRole (Blank)
        """
        handle = self._get_handle(context)
        self.playgrounder.delete_role(handle,
                                      request.role_name)
        return playground_pb2.DeleteRoleReply()

    def AddRole(self, request, context):
        """Adds a role to the model.

        Args:
            request (object): gRPC request
            context (object): gRPC context

        Returns:
            object: pb2 object of AddRole (Blank)
        """
        handle = self._get_handle(context)
        self.playgrounder.add_role(handle,
                                   request.role_name,
                                   request.permissions)
        return playground_pb2.AddRoleReply()


class GrpcPlaygrounderFactory(object):
    """Factory class for Playground service gRPC interface"""

    def __init__(self, config):
        """Initialize

        Args:
            config (object): ServiceConfig in server
        """
        self.config = config

    def create_and_register_service(self, server):
        """Creates a playground service and registers it in the server

        Args:
            server (object): Server to register service to.

        Returns:
            object: The instantiated gRPC service for playground.
        """

        service = GrpcPlaygrounder(
            playgrounder_api=playgrounder.Playgrounder(
                self.config))
        playground_pb2_grpc.add_PlaygroundServicer_to_server(service, server)
        LOGGER.info('Service %s created and registered', service)
        return service
