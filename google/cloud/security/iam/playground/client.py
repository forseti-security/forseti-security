#!/usr/bin/env python

import playground_pb2_grpc
import playground_pb2
import grpc
import time

def run():
	channel = grpc.insecure_channel('localhost:50051')
	stub = playground_pb2_grpc.PlaygroundStub(channel)
	request = playground_pb2.PingRequest()
	request.data = "hello"
	reply = stub.Ping(request)
	print reply.data == "hello"

if __name__ == "__main__":
	run()
