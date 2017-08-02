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

""" Gcs gRPC service. """

import time
from concurrent import futures
import grpc

from google.cloud.security.iam import iam_pb2
from google.cloud.security.iam.gcs import gcs_pb2_grpc
from google.cloud.security.iam.gcs import gcs
from google.cloud.security.iam.dao import session_creator


# TODO: The next editor must remove this disable and correct issues.
# pylint: disable=missing-type-doc,missing-return-type-doc,missing-return-doc
# pylint: disable=missing-param-doc,missing-yield-doc
# pylint: disable=missing-yield-type-doc


# pylint: disable=protected-access
def autoclose_stream(f):
    """Decorator to close gRPC stream."""

    def wrapper(*args):
        """Wrapper function, checks context state to close stream."""

        def closed(context):
            """Returns true iff the connection is closed."""

            return context._state.client == 'closed'
        context = args[-1]
        for result in f(*args):
            if closed(context):
                return
            yield result
    return wrapper


# pylint: disable=no-self-use
class GrpcGcs(gcs_pb2_grpc.GcsServicer):
    """Gcs policy gRPC implementation."""

    HANDLE_KEY = "handle"

    def _get_handle(self, context):
        """Return the handle associated with the gRPC call."""

        metadata = context.invocation_metadata()
        metadata_dict = {}
        for key, value in metadata:
            metadata_dict[key] = value
        return metadata_dict[self.HANDLE_KEY]

    def __init__(self, explainer_api):
        super(GrpcGcs, self).__init__()
        self.explainer = explainer_api

    def Ping(self, request, _):
        """Provides the capability to check for service availability."""

        return iam_pb2.PingReply(data=request.data)

    def GetAccessByPermissions(self, request, context):
        """Returns stream of access based on permission/role.

        Args:
            request (object): grpg request.
            context (object): grpg context.

        Yields:
            Generator for access tuples.
        """

        model_name = self._get_handle(context)

        for role, resource, members in (
                self.explainer.GetAccessByPermissions(
                    model_name,
                    request.role_name,
                    request.permission_name,
                    request.expand_groups,
                    request.expand_resources)):
            yield iam_pb2.Access(members=members,
                                 role=role,
                                 resource=resource)

    def GetAccessByResources(self, request, context):
        """Returns members having access to the specified resource."""

        model_name = self._get_handle(context)
        mapping = self.explainer.GetAccessByResources(model_name,
                                                      request.resource_name,
                                                      request.permission_names,
                                                      request.expand_groups)
        accesses = []
        for role, members in mapping.iteritems():
            access = iam_pb2.GetAccessByResourcesReply.Access(
                role=role, resource=request.resource_name, members=members)
            accesses.append(access)

        reply = iam_pb2.GetAccessByResourcesReply()
        reply.accesses.extend(accesses)
        return reply

    def GetAccessByMembers(self, request, context):
        """Returns resources which can be accessed by the specified members."""

        model_name = self._get_handle(context)
        accesses = []
        for role, resources in\
            self.explainer.GetAccessByMembers(model_name,
                                              request.member_name,
                                              request.permission_names,
                                              request.expand_resources):

            access = iam_pb2.GetAccessByMembersReply.Access(
                role=role, resources=resources, member=request.member_name)
            accesses.append(access)
        reply = iam_pb2.GetAccessByMembersReply()
        reply.accesses.extend(accesses)
        return reply

    def Denormalize(self, _, context):
        """Denormalize the entire model into access triples."""

        model_name = self._get_handle(context)

        for permission, resource, member in self.explainer.Denormalize(
                model_name):
            yield iam_pb2.AuthorizationTuple(member=member,
                                             permission=permission,
                                             resource=resource)


class GrpcGcsFactory(object):
    """Factory class for GCS explain gRPC interface"""

    def __init__(self, config):
        self.config = config

    def create_and_register_service(self, server):
        """Create and register the IAM Explain service."""

        service = GrpcGcs(explainer_api=gcs.Gcs(self.config))
        gcs_pb2_grpc.add_GcsServicer_to_server(service, server)
        return service


def serve(endpoint, config, max_workers=10, wait_shutdown_secs=3):
    """Serve Gcs Policy Explain with the provided parameters."""

    server = grpc.server(futures.ThreadPoolExecutor(max_workers))
    GrpcGcsFactory(config).create_and_register_service(server)
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
        """Dummy configuration."""

        def __init__(self):
            self.session_creator = session_creator('/tmp/explain.db')

        def run_in_background(self, function):
            """Run function in background."""

            function()

    import sys
    serve(endpoint=sys.argv[1] if len(sys.argv) >
          1 else '[::]:50051', config=DummyConfig())
