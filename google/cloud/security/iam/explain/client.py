#!/usr/bin/env python

import explain_pb2_grpc
import explain_pb2
import grpc
import time

def run():
	channel = grpc.insecure_channel(':50051')
	stub = explain_pb2_grpc.ExplainStub(channel)
	request = explain_pb2.PingRequest()
	request.data = "hello"
	reply = stub.Ping(request)
	print reply.data == "hello"

if __name__ == "__main__":
	run()
