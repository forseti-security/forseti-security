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

""" IAM Explain gRPC client. """

import binascii
import os
import grpc

from google.cloud.security.iam.explain import explain_pb2_grpc, explain_pb2
from google.cloud.security.iam.playground import playground_pb2_grpc
from google.cloud.security.iam.playground import playground_pb2
from google.cloud.security.iam.utils import oneof


def require_model(f):
    """Decorator to perform check that the model handle exists in the service.
    """

    def wrapper(*args, **kwargs):
        """Function wrapper to perform model handle existence check."""
        if args[0].config.handle():
            return f(*args, **kwargs)
        raise Exception("API requires model to be set")
    return wrapper


class ClientConfig(dict):
    """Provide access to client configuration data."""

    def handle(self):
        """Return currently active handle."""
        return self['handle']


class IAMClient(object):
    """Client base class."""

    def __init__(self, config):
        self.config = config

    def metadata(self):
        """Create default metadata for gRPC call."""
        return [('handle', self.config.handle())]


class ExplainClient(IAMClient):
    """Explain service allows the client to reason about a model.

    Explain provides the following functionality:
       - List access by resource/member
       - Provide information on why a member has access
       - Provide recommendations on how to provide access
    """

    def __init__(self, config):
        super(ExplainClient, self).__init__(config)
        self.stub = explain_pb2_grpc.ExplainStub(config['channel'])

    def is_available(self):
        """Checks if the 'Explain' service is available by performing a ping."""

        data = binascii.hexlify(os.urandom(16))
        return self.stub.Ping(explain_pb2.PingRequest(data=data)).data == data

    def new_model(self, source):
        """Creates a new model, reply contains the handle."""

        return self.stub.CreateModel(
            explain_pb2.CreateModelRequest(
                type=source))

    def list_models(self):
        """List existing models in the service."""

        return self.stub.ListModel(explain_pb2.ListModelRequest())

    def delete_model(self, model_name):
        """Delete a model, deletes all corresponding data."""

        return self.stub.DeleteModel(
            explain_pb2.DeleteModelRequest(
                handle=model_name),
            metadata=self.metadata())

    def explain_denied(self, member_name, resource_names, roles=None,
                       permission_names=None):
        """List possibilities to grant access which is currently denied."""

        roles = [] if roles is None else roles
        permission_names = [] if permission_names is None else permission_names
        if not oneof(roles != [], permission_names != []):
            raise Exception('Either roles or permission names must be set')
        request = explain_pb2.ExplainDeniedRequest(
            member=member_name,
            resources=resource_names,
            roles=roles,
            permissions=permission_names)
        return self.stub.ExplainDenied(request, metadata=self.metadata())

    def explain_granted(self, member_name, resource_name, role=None,
                        permission=None):
        """Provide data on all possibilities on
           how a member has access to a resources."""

        if not oneof(role is not None, permission is not None):
            raise Exception('Either role or permission name must be set')
        request = explain_pb2.ExplainGrantedRequest()
        if role is not None:
            request.role = role
        else:
            request.permission = permission
        request.resource = resource_name
        request.member = member_name
        return self.stub.ExplainGranted(request, metadata=self.metadata())

    @require_model
    def query_access_by_resources(self, resource_name, permission_names,
                                  expand_groups=False):
        """List members who have access to a given resource."""

        request = explain_pb2.GetAccessByResourcesRequest(
            resource_name=resource_name,
            permission_names=permission_names,
            expand_groups=expand_groups)
        return self.stub.GetAccessByResources(
            request, metadata=self.metadata())

    @require_model
    def query_access_by_members(self, member_name, permission_names,
                                expand_resources=False):
        """List resources to which a set of members has access to."""

        request = explain_pb2.GetAccessByMembersRequest(
            member_name=member_name,
            permission_names=permission_names,
            expand_resources=expand_resources)
        return self.stub.GetAccessByMembers(request, metadata=self.metadata())

    @require_model
    def query_permissions_by_roles(self, role_names=None, role_prefixes=None):
        """List all the permissions per given roles."""

        role_names = [] if role_names is None else role_names
        role_prefixes = [] if role_prefixes is None else role_prefixes
        request = explain_pb2.GetPermissionsByRolesRequest(
            role_names=role_names, role_prefixes=role_prefixes)
        return self.stub.GetPermissionsByRoles(
            request, metadata=self.metadata())

    @require_model
    def denormalize(self):
        """Denormalize the entire model into access triples."""

        return self.stub.Denormalize(
            explain_pb2.DenormalizeRequest(),
            metadata=self.metadata())


class PlaygroundClient(IAMClient):
    """Provides an interface to add entities into the IAM model.

        It allows the modification of:
           - Roles & Permissions
           - Membership relations
           - Resource hierarchy
           - Get/Set policies
           - Perform access checks
        This allows a client to perform simulations based on imported
        or empty models.
    """

    def __init__(self, config):
        super(PlaygroundClient, self).__init__(config)
        self.stub = playground_pb2_grpc.PlaygroundStub(config['channel'])

    def is_available(self):
        """Check if the Playground service is available."""

        data = binascii.hexlify(os.urandom(16))
        return self.stub.Ping(
            playground_pb2.PingRequest(
                data=data)).data == data

    @require_model
    def add_role(self, role_name, permissions):
        """Add a role associated with a list of permissions to the model."""

        return self.stub.AddRole(
            playground_pb2.AddRoleRequest(
                role_name=role_name,
                permissions=permissions),
            metadata=self.metadata())

    @require_model
    def del_role(self, role_name):
        """Delete a role from the model."""

        return self.stub.DelRole(
            playground_pb2.DelRoleRequest(
                role_name=role_name),
            metadata=self.metadata())

    @require_model
    def list_roles(self, role_name_prefix):
        """List roles by prefix, can be empty."""

        return self.stub.ListRoles(
            playground_pb2.ListRolesRequest(
                prefix=role_name_prefix),
            metadata=self.metadata())

    @require_model
    def add_resource(self, full_resource_name, resource_type,
                     parent_full_resource_name, no_parent=False):
        """Add a resource to the hierarchy."""

        return self.stub.AddResource(
            playground_pb2.AddResourceRequest(
                full_resource_name=full_resource_name,
                resource_type=resource_type,
                parent_full_resource_name=parent_full_resource_name,
                no_require_parent=no_parent),
            metadata=self.metadata())

    @require_model
    def del_resource(self, full_resource_name):
        """Delete a resource from the hierarchy and the subtree."""

        return self.stub.DelResource(
            playground_pb2.DelResourceRequest(
                full_resource_name=full_resource_name),
            metadata=self.metadata())

    @require_model
    def list_resources(self, resource_name_prefix):
        """List resources by name prefix."""

        return self.stub.ListResources(
            playground_pb2.ListResourcesRequest(
                prefix=resource_name_prefix),
            metadata=self.metadata())

    @require_model
    def add_member(self, member_type_name, parent_type_names=None):
        """Add a member to the member relationship."""

        if parent_type_names is None:
            parent_type_names = []
        return self.stub.AddGroupMember(
            playground_pb2.AddGroupMemberRequest(
                member_type_name=member_type_name,
                parent_type_names=parent_type_names),
            metadata=self.metadata())

    @require_model
    def del_member(self, member_name, parent_name=None,
                   only_delete_relationship=False):
        """Delete a member from the member relationship."""

        return self.stub.DelGroupMember(
            playground_pb2.DelGroupMemberRequest(
                member_name=member_name,
                parent_name=parent_name,
                only_delete_relationship=only_delete_relationship),
            metadata=self.metadata())

    @require_model
    def list_members(self, member_name_prefix):
        """List members by prefix."""

        return self.stub.ListGroupMembers(
            playground_pb2.ListGroupMembersRequest(
                prefix=member_name_prefix),
            metadata=self.metadata())

    @require_model
    def set_iam_policy(self, full_resource_name, policy):
        """Set the IAM policy on the resource."""

        bindingspb = [
            playground_pb2.Binding(
                role=role,
                members=members) for role,
            members in policy['bindings'].iteritems()]
        policypb = playground_pb2.Policy(
            bindings=bindingspb, etag=policy['etag'])
        return self.stub.SetIamPolicy(
            playground_pb2.SetIamPolicyRequest(
                resource=full_resource_name,
                policy=policypb),
            metadata=self.metadata())

    @require_model
    def get_iam_policy(self, full_resource_name):
        """Get the IAM policy from the resource."""

        return self.stub.GetIamPolicy(
            playground_pb2.GetIamPolicyRequest(
                resource=full_resource_name),
            metadata=self.metadata())

    @require_model
    def check_iam_policy(self, full_resource_name, permission_name,
                         member_name):
        """Check access via IAM policy."""

        return self.stub.CheckIamPolicy(
            playground_pb2.CheckIamPolicyRequest(
                resource=full_resource_name,
                permission=permission_name,
                identity=member_name),
            metadata=self.metadata())

class ClientComposition(object):
    """Client composition class.

        Most convenient to use since it comprises the common use cases among
        the different services.
    """

    DEFAULT_ENDPOINT = 'localhost:50058'
    def __init__(self, endpoint=DEFAULT_ENDPOINT):
        self.channel = grpc.insecure_channel(endpoint)
        self.config = ClientConfig({'channel': self.channel, 'handle': ''})

        self.explain = ExplainClient(self.config)
        self.playground = PlaygroundClient(self.config)

        self.clients = [self.explain, self.playground]
        if not all([c.is_available() for c in self.clients]):
            raise Exception('gRPC connected but services not registered')

    def new_model(self, source):
        """Create a new model from the specified source."""

        return self.explain.new_model(source)

    def list_models(self):
        """List existing models."""

        return self.explain.list_models()

    def switch_model(self, model_name):
        """Switch the client into using a model."""

        self.config['handle'] = model_name

    def delete_model(self, model_name):
        """Delete a model. Deletes all associated data."""

        return self.explain.delete_model(model_name)
