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

""" Explain gRPC service. """

from collections import defaultdict

from google.cloud.forseti.services.explain import explain_pb2
from google.cloud.forseti.services.explain import explain_pb2_grpc
from google.cloud.forseti.services.explain import explainer
from google.cloud.forseti.services.utils import autoclose_stream

# TODO: The next editor must remove this disable and correct issues.
# pylint: disable=missing-type-doc,missing-return-type-doc,missing-return-doc
# pylint: disable=missing-param-doc,missing-yield-doc
# pylint: disable=missing-yield-type-doc,no-member


class GrpcExplainer(explain_pb2_grpc.ExplainServicer):
    """IAM Explain gRPC implementation."""

    HANDLE_KEY = "handle"

    def _get_handle(self, context):
        """Return the handle associated with the gRPC call."""

        metadata = context.invocation_metadata()
        metadata_dict = {}
        for key, value in metadata:
            metadata_dict[key] = value
        return metadata_dict[self.HANDLE_KEY]

    def __init__(self, explainer_api):
        super(GrpcExplainer, self).__init__()
        self.explainer = explainer_api

    def Ping(self, request, _):
        """Provides the capability to check for service availability."""

        return explain_pb2.PingReply(data=request.data)

    def ExplainDenied(self, request, context):
        """Provides information on how to grant access."""

        model_name = self._get_handle(context)
        binding_strategies = self.explainer.ExplainDenied(model_name,
                                                          request.member,
                                                          request.resources,
                                                          request.permissions,
                                                          request.roles)
        reply = explain_pb2.ExplainDeniedReply()
        strategies = []
        for overgranting, bindings in binding_strategies:
            strategy = explain_pb2.BindingStrategy(overgranting=overgranting)
            strategy.bindings.extend([explain_pb2.Binding(
                member=b[1], resource=b[2], role=b[0]) for b in bindings])
            strategies.append(strategy)
        reply.strategies.extend(strategies)
        return reply

    def ExplainGranted(self, request, context):
        """Provides information on why a member has access to a resource."""

        model_name = self._get_handle(context)
        result = self.explainer.ExplainGranted(model_name,
                                               request.member,
                                               request.resource,
                                               request.role,
                                               request.permission)
        reply = explain_pb2.ExplainGrantedReply()
        bindings, member_graph, resource_names = result
        memberships = []
        for child, parents in member_graph.iteritems():
            memberships.append(
                explain_pb2.Membership(
                    member=child,
                    parents=parents))
        reply.memberships.extend(memberships)
        reply.resource_ancestors.extend(resource_names)
        reply.bindings.extend(
            [explain_pb2.Binding(member=member, resource=resource, role=role)
             for resource, role, member in bindings])
        return reply

    @autoclose_stream
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
            yield explain_pb2.Access(members=members,
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
            access = explain_pb2.GetAccessByResourcesReply.Access(
                role=role, resource=request.resource_name, members=members)
            accesses.append(access)

        reply = explain_pb2.GetAccessByResourcesReply()
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

            access = explain_pb2.GetAccessByMembersReply.Access(
                role=role, resources=resources, member=request.member_name)
            accesses.append(access)
        reply = explain_pb2.GetAccessByMembersReply()
        reply.accesses.extend(accesses)
        return reply

    def GetPermissionsByRoles(self, request, context):
        """Returns permissions for the specified roles."""

        model_name = self._get_handle(context)
        result = self.explainer.GetPermissionsByRoles(model_name,
                                                      request.role_names,
                                                      request.role_prefixes)

        permissions_by_roles_map = defaultdict(list)
        for role, permission in result:
            permissions_by_roles_map[role.name].append(permission.name)

        permissions_by_roles_list = []
        for role, permissions in permissions_by_roles_map.iteritems():
            permissions_by_roles_list.append(
                explain_pb2.GetPermissionsByRolesReply.PermissionsByRole(
                    role=role, permissions=permissions))

        reply = explain_pb2.GetPermissionsByRolesReply()
        reply.permissionsbyroles.extend(permissions_by_roles_list)
        return reply

    @autoclose_stream
    def Denormalize(self, _, context):
        """Denormalize the entire model into access triples."""

        model_name = self._get_handle(context)

        for permission, resource, member in self.explainer.Denormalize(
                model_name):
            yield explain_pb2.AuthorizationTuple(member=member,
                                                 permission=permission,
                                                 resource=resource)


class GrpcExplainerFactory(object):
    """Factory class for Explain service gRPC interface"""

    def __init__(self, config):
        self.config = config

    def create_and_register_service(self, server):
        """Create and register the IAM Explain service."""

        service = GrpcExplainer(explainer_api=explainer.Explainer(self.config))
        explain_pb2_grpc.add_ExplainServicer_to_server(service, server)
        return service
