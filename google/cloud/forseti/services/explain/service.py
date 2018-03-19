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
from google.cloud.forseti.common.util import logger

# pylint: disable=no-member

LOGGER = logger.get_logger(__name__)


class GrpcExplainer(explain_pb2_grpc.ExplainServicer):
    """Explain gRPC implementation."""

    HANDLE_KEY = 'handle'

    def _get_handle(self, context):
        """Return the handle associated with the gRPC call.

        Args:
            context (object): gRPC context

        Returns:
            str: handle of the GRPC call
        """
        metadata = context.invocation_metadata()
        metadata_dict = {}
        for key, value in metadata:
            metadata_dict[key] = value
        return metadata_dict[self.HANDLE_KEY]

    def __init__(self, explainer_api):
        """Initialize

        Args:
            explainer_api (object): explainer library
        """
        super(GrpcExplainer, self).__init__()
        self.explainer = explainer_api

    def Ping(self, request, _):
        """Provides the capability to check for service availability.

        Args:
            request (object): gRPC request.
            _ (object): Not used

        Returns:
            object: proto message of ping
        """

        return explain_pb2.PingReply(data=request.data)

    def ListResources(self, request, context):
        """Lists resources in the model.

        Args:
            request (object): gRPC request.
            context (object): gRPC context.

        Returns:
            object: proto message of list of resources
        """
        handle = self._get_handle(context)
        resources = self.explainer.list_resources(handle,
                                                  request.prefix)
        reply = explain_pb2.ListResourcesReply()
        reply.full_resource_names.extend([r.type_name for r in resources])
        return reply

    def ListGroupMembers(self, request, context):
        """Lists members in the model.

        Args:
            request (object): gRPC request.
            context (object): gRPC context.

        Returns:
            object: proto message of list of members
        """
        handle = self._get_handle(context)
        member_names = self.explainer.list_group_members(handle,
                                                         request.prefix)
        reply = explain_pb2.ListGroupMembersReply()
        reply.member_names.extend(member_names)
        return reply

    def ListRoles(self, request, context):
        """List roles from the model.

        Args:
            request (object): gRPC request.
            context (object): gRPC context.

        Returns:
            object: proto message of list of roles
        """
        handle = self._get_handle(context)
        role_names = self.explainer.list_roles(handle,
                                               request.prefix)
        reply = explain_pb2.ListRolesReply()
        reply.role_names.extend(role_names)
        return reply

    def GetIamPolicy(self, request, context):
        """Gets the policy for a resource.

        Args:
            request (object): gRPC request.
            context (object): gRPC context.

        Returns:
            object: proto message of IAM policy
        """
        handle = self._get_handle(context)
        policy = self.explainer.get_iam_policy(handle,
                                               request.resource)

        reply = explain_pb2.GetIamPolicyReply()

        etag = policy['etag']
        bindings = []
        for key, value in policy['bindings'].iteritems():
            binding = explain_pb2.BindingOnResource()
            binding.role = key
            binding.members.extend(value)
            bindings.append(binding)

        reply.resource = request.resource
        reply.policy.bindings.extend(bindings)
        reply.policy.etag = etag
        return reply

    def CheckIamPolicy(self, request, context):
        """Checks access according to policy to a specified resource.

        Args:
            request (object): gRPC request.
            context (object): gRPC context.

        Returns:
            object: proto message of whether access granted
        """
        handle = self._get_handle(context)
        authorized = self.explainer.check_iam_policy(handle,
                                                     request.resource,
                                                     request.permission,
                                                     request.identity)
        reply = explain_pb2.CheckIamPolicyReply()
        reply.result = authorized
        return reply

    def ExplainDenied(self, request, context):
        """Provides information on how to grant access.

        Args:
            request (object): gRPC request.
            context (object): gRPC context.

        Returns:
            object: proto message of explain denied result
        """
        model_name = self._get_handle(context)
        binding_strategies = self.explainer.explain_denied(model_name,
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
        """Provides information on why a member has access to a resource.

        Args:
            request (object): gRPC request.
            context (object): gRPC context.

        Returns:
            object: proto message of explain granted result
        """
        model_name = self._get_handle(context)
        result = self.explainer.explain_granted(model_name,
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
            request (object): grpc request.
            context (object): grpc context.

        Yields:
            object: Generator for access tuples.
        """
        model_name = self._get_handle(context)
        for role, resource, members in (
                self.explainer.get_access_by_permissions(
                    model_name,
                    request.role_name,
                    request.permission_name,
                    request.expand_groups,
                    request.expand_resources)):
            yield explain_pb2.Access(members=members,
                                     role=role,
                                     resource=resource)

    def GetAccessByResources(self, request, context):
        """Returns members having access to the specified resource.

        Args:
            request (object): gRPC request.
            context (object): gRPC context.

        Returns:
            object: proto message of access tuples by resource
        """
        model_name = self._get_handle(context)
        mapping = self.explainer.get_access_by_resources(
            model_name,
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
        """Returns resources which can be accessed by the specified members.

        Args:
            request (object): gRPC request.
            context (object): gRPC context.

        Returns:
            object: proto message of access tuples by members
        """
        model_name = self._get_handle(context)
        accesses = []
        for role, resources in \
                self.explainer.get_access_by_members(model_name,
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
        """Returns permissions for the specified roles.

        Args:
            request (object): gRPC request.
            context (object): gRPC context.

        Returns:
            object: proto message of access tuples by permission
        """
        model_name = self._get_handle(context)
        result = self.explainer.get_permissions_by_roles(model_name,
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


class GrpcExplainerFactory(object):
    """Factory class for Explain service gRPC interface"""

    def __init__(self, config):
        """Initialize

        Args:
            config (object): ServiceConfig in server
        """
        self.config = config

    def create_and_register_service(self, server):
        """Create and register the Explain service.

        Args:
            server (object): Server to register service to.

        Returns:
            object: The instantiated gRPC service for Explainer.
        """
        service = GrpcExplainer(explainer_api=explainer.Explainer(self.config))
        explain_pb2_grpc.add_ExplainServicer_to_server(service, server)
        LOGGER.info('Service %s created and registered.', service)
        return service
