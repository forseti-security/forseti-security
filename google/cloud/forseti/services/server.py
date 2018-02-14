# Copyright 2017 The Forseti Security Authors. All rights reserved.
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

"""Forseti Server program."""

# pylint: disable=line-too-long

import argparse

from abc import ABCMeta, abstractmethod
from multiprocessing.pool import ThreadPool
import time
from concurrent import futures
import grpc

from google.cloud.forseti.services.client import ClientComposition
from google.cloud.forseti.services import db
from google.cloud.forseti.services.dao import ModelManager, create_engine
from google.cloud.forseti.services.explain.service import GrpcExplainerFactory
from google.cloud.forseti.services.inventory.service import GrpcInventoryFactory
from google.cloud.forseti.services.inventory.storage import Storage
from google.cloud.forseti.services.model.service import GrpcModellerFactory
from google.cloud.forseti.services.notifier.service import GrpcNotifierFactory
from google.cloud.forseti.services.playground.service import GrpcPlaygrounderFactory
from google.cloud.forseti.services.scanner.service import GrpcScannerFactory

from google.cloud.forseti.common.util import logger

STATIC_SERVICE_MAPPING = {
    'explain': GrpcExplainerFactory,
    'playground': GrpcPlaygrounderFactory,
    'inventory': GrpcInventoryFactory,
    'scanner': GrpcScannerFactory,
    'notifier': GrpcNotifierFactory,
    'model': GrpcModellerFactory,
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

        Args:
            function (Function): Function to be executed.

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

    def get_root_resource_id(self):
        """Returns the root resource id.

        Raises:
            NotImplementedError: Abstract.
        """

        raise NotImplementedError()

    def get_gsuite_sa_path(self):
        """Returns gsuite service account path.

        Raises:
            NotImplementedError: Abstract.
        """

        raise NotImplementedError()

    def get_gsuite_admin_email(self):
        """Returns gsuite admin email.

        Raises:
            NotImplementedError: Abstract.
        """

        raise NotImplementedError()

    def get_service_config(self):
        """Returns the service config.

        Raises:
            NotImplementedError: Abstract.
        """

        raise NotImplementedError()


class InventoryConfig(AbstractInventoryConfig):
    """Implements composed dependency injection for the inventory."""

    def __init__(self,
                 root_resource_id,
                 gsuite_sa_path,
                 gsuite_admin_email,
                 *args,
                 **kwargs):
        """Args:
            root_resource_id(str): Root resource to start crawling from
            gsuite_sa_path(str): Path to G Suite service account private keyfile
            gsuite_admin_email(str): G Suite admin email
            args: args when creating InventoryConfig
            kwargs: kwargs when creating InventoryConfig
        """

        super(InventoryConfig, self).__init__(*args, **kwargs)
        self.service_config = None
        self.root_resource_id = root_resource_id
        self.gsuite_sa_path = gsuite_sa_path
        self.gsuite_admin_email = gsuite_admin_email

    def get_root_resource_id(self):
        """Return the configured root resource id.

        Returns:
            str: Root resource id.
        """

        return self.root_resource_id

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


class ServiceConfig(AbstractServiceConfig):
    """Implements composed dependency injection to Forseti Server services."""

    def __init__(self,
                 inventory_config,
                 forseti_db_connect_string,
                 forseti_config_file_path,
                 endpoint):
        """Args:
            inventory_config(InventoryConfig): the inventory_config
            forseti_db_connect_string(str): Forseti database string
            forseti_config_file_path(str): Path to Forseti configuration file.
            endpoint(str): server endpoint
        """

        super(ServiceConfig, self).__init__()
        self.thread_pool = ThreadPool()
        self.engine = create_engine(forseti_db_connect_string,
                                    pool_recycle=3600)
        self.model_manager = ModelManager(self.engine)
        self.sessionmaker = db.create_scoped_sessionmaker(self.engine)
        self.forseti_config_file_path = forseti_config_file_path
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
        """Runs a function in a thread pool in the background.

        Args:
            function (Function): Function to be executed.
        """

        self.thread_pool.apply_async(function)

    def get_storage_class(self):
        """Returns the storage class used to access the inventory.

        Returns:
            class: Type of a storage implementation.
        """

        return Storage


# pylint: disable=too-many-locals
def serve(endpoint, services,
          forseti_db_connect_string,
          forseti_config_file_path,
          gsuite_sa_path, gsuite_admin_email,
          root_resource_id, log_level,
          max_workers=32, wait_shutdown_secs=3):
    """Instantiate the services and serves them via gRPC.

    Args:
        endpoint(str): the server channel endpoint
        services(list): services to register on the server
        forseti_db_connect_string(str): Forseti database string
        forseti_config_file_path(str): Path to Forseti configuration file.
        gsuite_sa_path(str): Path to G Suite service account private keyfile
        gsuite_admin_email(str): G Suite admin email
        root_resource_id(str): Root resource to start crawling from
        log_level(str): Sets the threshold for Forseti's logger.
        max_workers(int): maximum number of workers for the crawler
        wait_shutdown_secs(int): seconds to wait before shutdown

    Raises:
        Exception: No services to start
    """

    factories = []
    for service in services:
        factories.append(STATIC_SERVICE_MAPPING[service])

    if not factories:
        raise Exception("No services to start")

    # Configuring log level for the application
    logger.set_logger_level_from_config(log_level)

    # Setting up configurations
    inventory_config = InventoryConfig(root_resource_id,
                                       gsuite_sa_path,
                                       gsuite_admin_email)
    config = ServiceConfig(inventory_config,
                           forseti_db_connect_string,
                           forseti_config_file_path,
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
# pylint: enable=too-many-locals


def main():
    """Run."""
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '--endpoint',
        default='[::]:50051',
        help='Server endpoint')
    parser.add_argument(
        '--forseti_db',
        help=('Forseti database string, formatted as '
              '"mysql://<db_user>@<db_host>:<db_port>/<db_name>"'))
    parser.add_argument(
        '--forseti_config_file_path',
        help=('Path to Forseti configuration file.'))
    parser.add_argument(
        '--gsuite_private_keyfile',
        help='Path to G Suite service account private keyfile')
    parser.add_argument(
        '--gsuite_admin_email',
        help='G Suite admin email')
    parser.add_argument(
        '--root_resource_id',
        help=('Root resource to start crawling from, formatted as '
              '"<resource_type>/<resource_id>" '
              '(e.g. "organizations/12345677890")'))
    parser.add_argument(
        '--services',
        nargs='*',
        default=[],
        help='Forseti services')
    parser.add_argument(
        '--log_level',
        default='info',
        choices=['debug', 'info', 'warning', 'error'],
        help="Sets the threshold for Forseti's logger."
             " Logging messages which are less severe"
             " than the level you set will be ignored.")
    args = vars(parser.parse_args())

    serve(args['endpoint'], args['services'], args['forseti_db'],
          args['forseti_config_file_path'], args['gsuite_private_keyfile'],
          args['gsuite_admin_email'], args['root_resource_id'],
          args['log_level'])


if __name__ == "__main__":
    main()
