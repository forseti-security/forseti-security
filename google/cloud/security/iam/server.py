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

from google.cloud.security.iam.client import ClientComposition
from google.cloud.security.iam import db
from google.cloud.security.iam.dao import ModelManager, create_engine
from google.cloud.security.iam.explain.service import GrpcExplainerFactory
from google.cloud.security.iam.playground.service import GrpcPlaygrounderFactory
from google.cloud.security.iam.inventory.service import GrpcInventoryFactory

STATIC_SERVICE_MAPPING = {
    'explain': GrpcExplainerFactory,
    'playground': GrpcPlaygrounderFactory,
    'inventory': GrpcInventoryFactory,
}


# TODO: The next editor must remove this disable and correct issues.
# pylint: disable=missing-param-doc,missing-type-doc,missing-raises-doc,too-many-instance-attributes


class ServiceConfig(object):
    """Implements composed dependency injection to IAM Explain services."""

    def __init__(self,
                 explain_connect_string,
                 forseti_connect_string,
                 endpoint,
                 gsuite_sa_path,
                 gsuite_admin_email,
                 organization_id):

        self.thread_pool = ThreadPool()
        self.engine = create_engine(explain_connect_string, pool_recycle=3600)
        self.model_manager = ModelManager(self.engine)
        self.forseti_connect_string = forseti_connect_string
        self.sessionmaker = db.create_scoped_sessionmaker(self.engine)
        self.endpoint = endpoint
        self.gsuite_sa_path = gsuite_sa_path
        self.gsuite_admin_email = gsuite_admin_email
        self.organization_id = organization_id

    def get_organization_id(self):
        """Get the organization id.

        Returns:
            str: The configure organization id.
        """

        return self.organization_id

    def get_gsuite_sa_path(self):
        """Get path to gsuite service account.

        Returns:
            str: Gsuite admin service account path.
        """

        return self.gsuite_sa_path

    def get_gsuite_admin_email(self):
        """Get the gsuite admin email.

        Returns:
            str: Gsuite admin email address to impersonate.
        """

        return self.gsuite_admin_email

    def get_engine(self):
        """Get the database engine.

        Returns:
            object: Database engine object.
        """

        return self.engine

    def scoped_session(self):
        """Get a scoped session.

        Returns:
            object: A scoped session.
        """

        return self.sessionmaker()

    def client(self):
        """Get an API client.

        Returns:
            object: API client to use against services.
        """

        return ClientComposition(self.endpoint)

    def run_in_background(self, function):
        """Runs a function in a thread pool in the background."""

        self.thread_pool.apply_async(function)


def serve(endpoint, services,
          explain_connect_string, forseti_connect_string,
          gsuite_sa_path, gsuite_admin_email,
          organization_id, max_workers=32, wait_shutdown_secs=3):
    """Instantiate the services and serves them via gRPC."""

    factories = []
    for service in services:
        factories.append(STATIC_SERVICE_MAPPING[service])

    if not factories:
        raise Exception("No services to start")

    config = ServiceConfig(explain_connect_string,
                           forseti_connect_string,
                           endpoint,
                           gsuite_sa_path,
                           gsuite_admin_email,
                           organization_id)
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
    FORSETI_DB = sys.argv[2] if len(sys.argv) > 2 else ''
    EXPLAIN_DB = sys.argv[3] if len(sys.argv) > 3 else ''
    GSUITE_SA = sys.argv[4] if len(sys.argv) > 4 else ''
    GSUITE_ADMIN_EMAIL = sys.argv[5] if len(sys.argv) > 5 else ''
    ORGANIZATION_ID = sys.argv[6] if len(sys.argv) > 6 else ''
    SVCS = sys.argv[7:] if len(sys.argv) > 7 else []
    serve(EP, SVCS, EXPLAIN_DB, FORSETI_DB,
          GSUITE_SA, GSUITE_ADMIN_EMAIL, ORGANIZATION_ID)
