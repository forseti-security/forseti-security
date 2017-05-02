#!/usr/bin/env python

from explain import explain_pb2_grpc
from explain import explain_pb2
from playground import playground_pb2_grpc
from playground import playground_pb2

import grpc

def usePlayground(channel):
    stub = playground_pb2_grpc.PlaygroundStub(channel)
    request = playground_pb2.PingRequest()
    request.data = 'ehlo'
    reply = stub.Ping(request)
    return reply.data == 'ehlo'
    
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

def run():
    channel = grpc.insecure_channel('localhost:50051')
    usePlayground(channel)
    useExplain(channel)

if __name__ == "__main__":
    run()
