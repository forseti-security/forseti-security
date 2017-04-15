#!/usr/bin/env python

from concurrent import futures
import time
import grpc

from explain.service import Explainer, registerWithServer as registerExplainer
from playground.service import Playgrounder, registerWithServer as registerPlaygrounder

def serve(endpoint='[::]:50051', max_workers=10, wait_shutdown_secs=3):
    server = grpc.server(futures.ThreadPoolExecutor(max_workers))
    
    registerExplainer(Explainer(), server)
    registerPlaygrounder(Playgrounder(), server)

    server.add_insecure_port(endpoint)
    server.start()
    while True:
        try:
            time.sleep(1)
        except KeyboardInterrupt:
            server.stop(wait_shutdown_secs).wait()
            return

if __name__ == "__main__":
    serve()

