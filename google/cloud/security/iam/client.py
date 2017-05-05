#!/usr/bin/env python

from explain import explain_pb2_grpc
from explain import explain_pb2
from playground import playground_pb2_grpc
from playground import playground_pb2

import binascii
import os
import grpc

def require_model(f):
    def wrapper(*args):
        if args[0].config.handle() != "":
            return f(*args)
        raise Exception("API requires model to be set")
    return wrapper

class ClientConfig(dict):
    def handle(self):
        return self['handle']

class IAMClient(object):
    def __init__(self, config):
        self.config = config
        
    def metadata(self):
        return [('handle', self.config.handle())]

class ExplainClient(IAMClient):
    def __init__(self, config):
        super(ExplainClient, self).__init__(config)
        self.stub = explain_pb2_grpc.ExplainStub(config['channel'])

    def is_available(self):
        data = binascii.hexlify(os.urandom(16))
        return self.stub.Ping(explain_pb2.PingRequest(data=data)).data == data
    
    def new_model(self, source):
        return self.stub.CreateModel(explain_pb2.CreateModelRequest(type=source))

    def list_models(self):
        return self.stub.ListModel(explain_pb2.ListModelRequest())
    
    def delete_model(self, model_name):
        return self.stub.DeleteModel(explain_pb2.DeleteModelRequest(handle=model_name), metadata=self.metadata())

    @require_model
    def query_access_by_resources(self):
        raise NotImplementedError()

    @require_model
    def query_access_by_members(self):
        raise NotImplementedError()

    @require_model
    def query_permissions_by_roles(self):
        raise NotImplementedError()

    @require_model
    def denormalize(self):
        return self.stub.Denormalize(explain_pb2.DenormalizeRequest(), metadata=self.metadata())

class PlaygroundClient(IAMClient):
    def __init__(self, config):
        super(PlaygroundClient, self).__init__(config)
        self.stub = playground_pb2_grpc.PlaygroundStub(config['channel'])

    def is_available(self):
        data = binascii.hexlify(os.urandom(16))
        return self.stub.Ping(playground_pb2.PingRequest(data=data)).data == data
    
    @require_model
    def add_role(self, role_name, permissions):
        return self.stub.AddRole(playground_pb2.AddRoleRequest(role_name=role_name, permissions=permissions), metadata=self.metadata())
    
    @require_model
    def del_role(self, role_name):
        return self.stub.DelRole(playground_pb2.DelRoleRequest(role_name=role_name), metadata=self.metadata())
    
    @require_model
    def list_roles(self, role_name_prefix):
        return self.stub.ListRoles(playground_pb2.ListRoleRequest(prefix=role_name_prefix), metadata=self.metadata())

    @require_model
    def add_resource(self, full_resource_name, resource_type, parent_full_resource_name, no_parent=False):
        return self.stub.AddResource(playground_pb2.AddResourceRequest(full_resource_name=full_resource_name, resource_type=resource_type, parent_full_resource_nmae=parent_full_resource_name, no_require_parent=no_parent), self.metadata())
    
    @require_model
    def del_resource(self, full_resource_name):
        return self.stub.DelResource(playground_pb2.DelResourceRequest(full_resource_name=full_resource_name), metadata=self.metadata())
    
    @require_model
    def list_resources(self, resource_name_prefix):
        return self.stub.ListResources(playground_pb2.ListResourcesRequest(prefix=resource_name_prefix), metadata=self.metadata())

    @require_model
    def add_member(self, member_name, member_type, parent_names):
        return self.stub.AddGroupMember(playground_pb2.AddGroupMemberRequest(member_name=member_name, member_type=member_type, parent_names=parent_names), metadata=self.metadata())

    @require_model
    def del_member(self, member_name, parent_name=None, only_delete_relationship=False):
        return self.stub.DelGroupMember(playground_pb2.DelGroupMemberRequest(member_name=member_name, parent_name=parent_name, only_delete_relationship=only_delete_relationship), metadata=self.metadata())

    @require_model
    def list_members(self, member_name_prefix):
        return self.stub.ListGroupMembers(playground_pb2.ListGroupMembersRequest(), metadata=self.metadata())

    @require_model
    def set_iam_policy(self, full_resource_name, policy):
        bindingspb = [playground_pb2.Binding(role=role, members=members) for role, members in policy['bindings'].iteritems()]
        policypb = playground_pb2.Policy(bindings=bindingspb)
        return self.stub.SetIamPolicy(playground_pb2.SetIamPolicyRequest(resource=full_resource_name, policy=policypb), metadata=self.metadata())

    @require_model
    def get_iam_policy(self, full_resource_name):
        return self.stub.GetIamPolicy(playground_pb2.GetIamPolicyRequest(resource=full_resource_name), metadata=self.metadata())

    @require_model
    def check_iam_policy(self, full_resource_name, permission_name, member_name):
        return self.stub.CheckIamPolicy(playground_pb2.CheckIamPolicyRequest(resource=full_resource_name, permission=permission_name, identity=member_name), metadata=self.metadata())

    def get_policy_template(self):
        return {'bindings':{}, 'etag':''}

class ClientComposition:
    def __init__(self, endpoint='localhost:50058'):
        self.channel = grpc.insecure_channel(endpoint)
        self.config = ClientConfig({'channel':self.channel, 'handle':''})

        self.explain = ExplainClient(self.config)
        self.playground = PlaygroundClient(self.config)

        self.clients = [self.explain, self.playground]
        if not all(map(lambda c: c.is_available(), self.clients)):
            raise Exception('gRPC connected but services not registered')

    def new_model(self, source):
        return self.explain.new_model(source)

    def list_models(self):
        return self.explain.list_models()

    def switch_model(self, model_name):
        self.config['handle'] = model_name

    def delete_model(self, model_name):
        return self.explain.delete_model(model_name)

if __name__ == "__main__":
    #run()
    client = ClientComposition()

