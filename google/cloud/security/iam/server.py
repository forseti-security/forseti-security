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
from google.protobuf.internal.test_bad_identifiers_pb2 import service

""" IAM Explain server program. """

from abc import ABCMeta, abstractmethod
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
from google.cloud.security.iam.inventory.storage import Storage


# TODO: The next editor must remove this disable and correct issues.
# pylint: disable=missing-param-doc,missing-type-doc,missing-raises-doc,too-many-instance-attributes


STATIC_SERVICE_MAPPING = {
    'explain': GrpcExplainerFactory,
    'playground': GrpcPlaygrounderFactory,
    'inventory': GrpcInventoryFactory,
}


class AbstractServiceConfig(object):
    """Abstract base class for service configuration. This class
    is used to implement dependency injection for the gRPC services."""

    __metaclass__ = ABCMeta

    @abstractmethod
    def get_engine(self):
        """Get the database engine.

        Raises:
            NotImplementedError: Abstract.
        """

        raise NotImplementedError()

    @abstractmethod
    def scoped_session(self):
        """Get a scoped session.

        Raises:
            NotImplementedError: Abstract.
        """

        raise NotImplementedError()

    @abstractmethod
    def client(self):
        """Get an API client.

        Raises:
            NotImplementedError: Abstract.
        """

        raise NotImplementedError()

    @abstractmethod
    def run_in_background(self, function):
        """Runs a function in a thread pool in the background.

        Raises:
            NotImplementedError: Abstract.
        """

        raise NotImplementedError()

    def get_storage_class(self):
        """Returns the class used for the inventory storage.

        Raises:
            NotImplementedError: Abstract.
        """

        raise NotImplementedError()


class AbstractInventoryConfig(dict):
    """Abstract base class for service configuration. This class
    is used to implement dependency injection for the gRPC services."""

    __metaclass__ = ABCMeta

    def __init__(self, *args, **kwargs):
        super(AbstractInventoryConfig, self).__init__(*args, **kwargs)

    def get_organization_id(self):
        raise NotImplementedError()

    def get_gsuite_sa_path(self):
        raise NotImplementedError()

    def get_gsuite_admin_email(self):
        raise NotImplementedError()

    def get_service_config(self):
        raise NotImplementedError()


class InventoryConfig(AbstractInventoryConfig):
    """Implements composed dependency injection for the inventory."""

    def __init__(self,
                 organization_id,
                 gsuite_sa_path,
                 gsuite_admin_email,
                 record_file=None,
                 replay_file=None,
                 *args,
                 **kwargs):

        super(InventoryConfig, self).__init__(*args, **kwargs)
        self.service_config = None
        self.organization_id = organization_id
        self.gsuite_sa_path = gsuite_sa_path
        self.gsuite_admin_email = gsuite_admin_email
        self.record_file = record_file
        self.replay_file = replay_file

    def get_organization_id(self):
        """Return the configured organization id.

        Returns:
            str: Organization ID.
        """

        return self.organization_id

    def get_gsuite_sa_path(self):
        """Return the gsuite service account path.

        Returns:
            str: Gsuite service account path.
        """

        return self.gsuite_sa_path

    def get_gsuite_admin_email(self):
        """Return the gsuite admin email to use.

        Returns:
            str: Gsuite admin email.
        """

        return self.gsuite_admin_email

    def get_service_config(self):
        """Return the attached service configuration.

        Returns:
            object: Service configuration.
        """

        return self.service_config

    def set_service_config(self, service_config):
        """Attach a service configuration.

        Args:
            service_config (object): Service configuration.
        """

        self.service_config = service_config

    def get_replay_file(self):
        """Return the replay file which is None most of the time.

        Returns:
            str: File to replay GCP API calls from.
        """

        return self.replay_file

    def get_record_file(self):
        """Return the record file which is None most of the time.

        Returns:
            str: File to record GCP API calls to.
        """

        return self.record_file


class ServiceConfig(AbstractServiceConfig):
    """Implements composed dependency injection to IAM Explain services."""

    def __init__(self,
                 inventory_config,
                 explain_connect_string,
                 forseti_connect_string,
                 endpoint):

        super(ServiceConfig, self).__init__()
        self.thread_pool = ThreadPool()
        self.engine = create_engine(explain_connect_string, pool_recycle=3600)
        self.model_manager = ModelManager(self.engine)
        self.forseti_connect_string = forseti_connect_string
        self.sessionmaker = db.create_scoped_sessionmaker(self.engine)
        self.endpoint = endpoint

        self.inventory_config = inventory_config
        self.inventory_config.set_service_config(self)

    def get_inventory_config(self):
        """Get the inventory config.

        Returns:
            object: Inventory config.
        """

        return self.inventory_config

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

    def get_storage_class(self):
        """Returns the storage class used to access the inventory.

        Returns:
            class: Type of a storage implementation.
        """

        return Storage


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

    # Setting up configurations
    inventory_config = InventoryConfig(organization_id,
                                       gsuite_sa_path,
                                       gsuite_admin_email)
    config = ServiceConfig(inventory_config,
                           explain_connect_string,
                           forseti_connect_string,
                           endpoint)
    inventory_config.set_service_config(config)

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
