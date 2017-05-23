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

""" IAM Explain server program. """

from multiprocessing.pool import ThreadPool
import time
from concurrent import futures
import grpc

from google.cloud.security.iam.dao import ModelManager, create_engine
from google.cloud.security.iam.explain.service import GrpcExplainerFactory
from google.cloud.security.iam.playground.service import GrpcPlaygrounderFactory

STATIC_SERVICE_MAPPING = {
    'explain': GrpcExplainerFactory,
    'playground': GrpcPlaygrounderFactory,
}


class ServiceConfig(object):
    """
    ServiceConfig is a helper class to implement dependency injection
    to IAM Explain services.
    """
    def __init__(self):
        self.thread_pool = ThreadPool()

        engine = create_engine('sqlite:///%s' % '/tmp/explain.db')
        self.model_manager = ModelManager(engine)

    def run_in_background(self, function):
        """Runs a function in a thread pool in the background."""
        self.thread_pool.apply_async(function)


def serve(endpoint, services, max_workers=1, wait_shutdown_secs=3):
    """Instantiate the services and serves them via gRPC."""

    factories = []
    for service in services:
        factories.append(STATIC_SERVICE_MAPPING[service])

    if not factories:
        raise Exception("No services to start")

    config = ServiceConfig()
    server = grpc.server(futures.ThreadPoolExecutor(max_workers))
    for factory in factories:
        factory(config).create_and_register_service(server)

    server.add_insecure_port(endpoint)
    server.start()
    while True:
        try:
            time.sleep(1)
        except KeyboardInterrupt:
            server.stop(wait_shutdown_secs).wait()
            return


if __name__ == "__main__":
    import sys
    EP = sys.argv[1] if len(sys.argv) > 1 else '[::]:50051'
    SVCS = sys.argv[2:] if len(sys.argv) > 2 else []
    serve(EP, SVCS)
