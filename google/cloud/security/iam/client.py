#!/usr/bin/env python

from explain import explain_pb2_grpc
from explain import explain_pb2
from playground import playground_pb2_grpc
from playground import playground_pb2

import grpc

def usePlayground(channel, handle):
    stub = playground_pb2_grpc.PlaygroundStub(channel)
    request = playground_pb2.PingRequest()
    request.data = 'ehlo'
    reply = stub.Ping(request)
    print reply.data == 'ehlo'

    request = playground_pb2.AddResourceRequest()
    request.full_resource_name = 'organization/test'
    request.resource_type = 'organization'
    request.no_require_parent = True
    reply = stub.AddResource(request, metadata=[("handle", handle)])
    print reply

    request = playground_pb2.AddResourceRequest()
    request.full_resource_name = 'project/fubar'
    request.resource_type = 'project'
    request.parent_full_resource_name = 'organization/test'
    reply = stub.AddResource(request, metadata=[("handle", handle)])
    print reply

    request = playground_pb2.ListResourcesRequest()
    request.prefix = ""
    reply = stub.ListResources(request, metadata=[("handle", handle)])
    print reply

    request = playground_pb2.DelResourceRequest()
    request.full_resource_name = 'organization/test'
    reply = stub.DelResource(request, metadata=[("handle", handle)])
    print reply

    request = playground_pb2.ListGroupMembersRequest()
    request.prefix = ""
    reply = stub.ListGroupMembers(request, metadata=[("handle", handle)])
    print reply

    request = playground_pb2.AddGroupMemberRequest()
    request.member_name = "felixfelixfelix"
    request.member_type = "the_felix"
    reply = stub.AddGroupMember(request, metadata=[('handle', handle)])
    print reply

    request = playground_pb2.AddGroupMemberRequest()
    request.member_name = "felixfelixfelix2"
    request.member_type = "the_felix"
    request.parent_names.extend(['felixfelixfelix'])
    reply = stub.AddGroupMember(request, metadata=[('handle', handle)])
    print reply

    request = playground_pb2.ListGroupMembersRequest()
    request.prefix = ""
    reply = stub.ListGroupMembers(request, metadata=[("handle", handle)])
    print reply

    request = playground_pb2.AddRoleRequest()
    request.role_name = "new_role"
    request.permissions.extend(["new_permission1","new_permission2"])
    reply = stub.AddRole(request, metadata=[("handle", handle)])
    print reply

    request = playground_pb2.ListRolesRequest()
    request.prefix = ""
    reply = stub.ListRoles(request, metadata=[("handle", handle)])
    print reply

    request = playground_pb2.GetIamPolicyRequest()
    request.resource = 'vm1'
    reply = stub.GetIamPolicy(request, metadata=[('handle', handle)])
    print reply
    last_etag = reply.policy.etag

    request = playground_pb2.CheckIamPolicyRequest()
    request.permission = 'cloudsql.table.read'
    request.resource = 'vm1'
    request.identity = 'group1'
    reply = stub.CheckIamPolicy(request, metadata=[('handle', handle)])
    print "First check: %s"%reply

    request = playground_pb2.CheckIamPolicyRequest()
    request.permission = 'cloudsql.table.write'
    request.resource = 'vm1'
    request.identity = 'group1'
    reply = stub.CheckIamPolicy(request, metadata=[('handle', handle)])
    print "Secpmd check: %s"%reply

    bindings = []
    b1 = playground_pb2.Binding()
    b1.role = 'sqlreader'
    b1.members.extend(['group2','felix','felixfelixfelix'])

    b2 = playground_pb2.Binding()
    b2.role = 'new_role'
    b2.members.extend(['group2','felix','felixfelixfelix2'])

    request = playground_pb2.SetIamPolicyRequest()
    request.resource = 'vm1'
    request.policy.etag = last_etag
    request.policy.bindings.extend([b1,b2])
    reply = stub.SetIamPolicy(request, metadata=[('handle', handle)])

    request = playground_pb2.GetIamPolicyRequest()
    request.resource = 'vm1'
    reply = stub.GetIamPolicy(request, metadata=[('handle', handle)])
    print reply


def useExplain(channel):
    stub = explain_pb2_grpc.ExplainStub(channel)
    request = explain_pb2.PingRequest()
    request.data = "hello"
    reply = stub.Ping(request)
    if reply.data != "hello":
        raise Exception()

    request = explain_pb2.CreateModelRequest()
    request.type = "TEST"
    reply = stub.CreateModel(request)
    print reply.handle

    handle = reply.handle
    request = explain_pb2.GetAccessByResourcesRequest()
    request.resource_name='vm1'
    request.expand_groups=True
    request.permission_names.extend(['cloudsql.table.read','cloudsql.table.write'])
    reply = stub.GetAccessByResources(request, metadata=[("handle",handle)])
    print reply

    request = explain_pb2.GetAccessByResourcesRequest()
    request.resource_name='vm1'
    request.expand_groups=False
    request.permission_names.extend(['cloudsql.table.read','cloudsql.table.write'])
    reply = stub.GetAccessByResources(request, metadata=[("handle",handle)])
    print reply

    request = explain_pb2.ListModelRequest()
    reply = stub.ListModel(request)
    print reply

    #request = explain_pb2.DeleteModelRequest()
    #request.handle = handle
    #reply = stub.DeleteModel(request)
    #print reply

    #request = explain_pb2.ListModelRequest()
    #reply = stub.ListModel(request)
    #print reply

    request = explain_pb2.DenormalizeRequest()
    reply = stub.Denormalize(request, metadata=[('handle', handle)])
    for tuple in reply:
        print tuple
    return handle

def run():
    channel = grpc.insecure_channel('localhost:50051')
    handle = useExplain(channel)
    usePlayground(channel, handle)

if __name__ == "__main__":
    run()

