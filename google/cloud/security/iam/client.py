#!/usr/bin/env python

import explain_pb2_grpc
import explain_pb2
import grpc
import time
import logging

def run():
    logging.info("Running client")
    channel = grpc.insecure_channel('localhost:50051')
    logging.info("Connected")
    stub = explain_pb2_grpc.ExplainStub(channel)
    logging.info("Instantiated client stub")
    request = explain_pb2.PingRequest()
    logging.info("Created request")
    request.data = "hello"
    reply = stub.Ping(request)
    logging.info("Executed RPC")
    print reply.data == "hello"

if __name__ == "__main__":
    print "Running"
    run()
