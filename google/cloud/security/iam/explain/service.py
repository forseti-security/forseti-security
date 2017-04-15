#!/usr/bin/env python

from concurrent import futures
import time
import grpc

import explain_pb2
import explain_pb2_grpc

class Explainer(explain_pb2_grpc.ExplainServicer):

	def Ping(self, request, context):
		return explain_pb2.PingReply(data=request.data)
        
def registerWithServer(explainer, server):
    explain_pb2_grpc.add_ExplainServicer_to_server(explainer, server)

def serve(endpoint='[::]:50051', max_workers=10, wait_shutdown_secs=3):
    server = grpc.server(futures.ThreadPoolExecutor(max_workers))
    registerWithServer(Explainer(), server)
    explain_pb2_grpc.add_ExplainServicer_to_server(Explainer(), server)
    server.add_insecure_port(endpoint)
    server.start()
    while True:
        try:
            time.sleep(1); print "Looping\n"
        except KeyboardInterrupt:
            server.stop(wait_shutdown_secs).wait()
            return

if __name__ == "__main__":
    serve()