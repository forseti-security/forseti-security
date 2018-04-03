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

from google.cloud.forseti.common.util import file_loader
from google.cloud.forseti.services.client import ClientComposition
from google.cloud.forseti.services import db
from google.cloud.forseti.services.dao import ModelManager
from google.cloud.forseti.services.dao import create_engine
from google.cloud.forseti.services.explain.service import GrpcExplainerFactory
from google.cloud.forseti.services.inventory.service import GrpcInventoryFactory
from google.cloud.forseti.services.inventory.storage import Storage
from google.cloud.forseti.services.model.service import GrpcModellerFactory
from google.cloud.forseti.services.notifier.service import GrpcNotifierFactory
from google.cloud.forseti.services.scanner.service import GrpcScannerFactory

from google.cloud.forseti.common.util import logger

LOGGER = logger.get_logger(__name__)

STATIC_SERVICE_MAPPING = {
    'explain': GrpcExplainerFactory,
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
    def run_in_background(self, func):
        """Runs a function in a thread pool in the background.

        Args:
            func (Function): Function to be executed.

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

    def get_api_quota_configs(self):
        """Returns the per API quota configs.

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
                 api_quota_configs,
                 *args,
                 **kwargs):
        """Initialize

        Args:
            root_resource_id (str): Root resource to start crawling from
            gsuite_sa_path (str): Path to G Suite service account private keyfile
            gsuite_admin_email (str): G Suite admin email
            api_quota_configs (dict): API quota configs
            args: args when creating InventoryConfig
            kwargs: kwargs when creating InventoryConfig
        """

        super(InventoryConfig, self).__init__(*args, **kwargs)
        self.service_config = None
        self.root_resource_id = root_resource_id
        self.gsuite_sa_path = gsuite_sa_path
        self.gsuite_admin_email = gsuite_admin_email
        self.api_quota_configs = api_quota_configs

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

    def get_api_quota_configs(self):
        """Returns the per API quota configs.

        Returns:
            dict: The API quota configurations.
        """

        return self.api_quota_configs

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


# pylint: disable=too-many-instance-attributes
class ServiceConfig(AbstractServiceConfig):
    """Implements composed dependency injection to Forseti Server services."""

    def __init__(self,
                 inventory_config,
                 scanner_config,
                 notifier_config,
                 global_config,
                 forseti_db_connect_string,
                 endpoint,
                 enable_debug_mode):
        """Initialize

        Args:
            inventory_config (InventoryConfig): the inventory_config
            scanner_config (dict): Scanner configurations
            notifier_config (dict): Notifier configurations
            global_config (dict): Global configurations
            forseti_db_connect_string (str): Forseti database string
            endpoint (str): server endpoint
            enable_debug_mode (bool): Enable console logging.
        """

        super(ServiceConfig, self).__init__()
        self.thread_pool = ThreadPool()
        self.engine = create_engine(forseti_db_connect_string,
                                    pool_recycle=3600)
        self.model_manager = ModelManager(self.engine)
        self.sessionmaker = db.create_scoped_sessionmaker(self.engine)
        self.endpoint = endpoint
        self.enable_debug_mode = enable_debug_mode

        self.inventory_config = inventory_config
        self.inventory_config.set_service_config(self)

        self.scanner_config = scanner_config
        self.notifier_config = notifier_config
        self.global_config = global_config

    def get_inventory_config(self):
        """Get the inventory config.

        Returns:
            object: Inventory config.
        """

        return self.inventory_config

    def get_scanner_config(self):
        """Get the scanner config.

        Returns:
            dict: Scanner config.
        """

        return self.scanner_config

    def get_notifier_config(self):
        """Get the notifier config.

        Returns:
            dict: Notifier config.
        """

        return self.notifier_config

    def get_global_config(self):
        """Get the global config.

        Returns:
            dict: Global config.
        """

        return self.global_config

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

    def run_in_background(self, func):
        """Runs a function in a thread pool in the background.

        Args:
            func (Function): Function to be executed.
        """

        self.thread_pool.apply_async(func)

    def get_storage_class(self):
        """Returns the storage class used to access the inventory.

        Returns:
            class: Type of a storage implementation.
        """

        return Storage


# pylint: enable=too-many-instance-attributes

# pylint: disable=too-many-locals
def serve(endpoint,
          services,
          forseti_db_connect_string,
          forseti_config_file_path,
          log_level,
          enable_console_log,
          enable_debug_mode,
          max_workers=32,
          wait_shutdown_secs=3):
    """Instantiate the services and serves them via gRPC.

    Args:
        endpoint (str): the server channel endpoint
        services (list): services to register on the server
        forseti_db_connect_string (str): Forseti database string
        forseti_config_file_path (str): Path to Forseti configuration file.
        log_level (str): Sets the threshold for Forseti's logger.
        enable_console_log (bool): Enable console logging.
        enable_debug_mode (bool): Enable console logging.
        max_workers (int): maximum number of workers for the crawler
        wait_shutdown_secs (int): seconds to wait before shutdown

    Raises:
        Exception: No services to start
    """

    # Configuring log level for the application
    logger.set_logger_level_from_config(log_level)

    if enable_console_log:
        logger.enable_console_log()

    factories = []
    for service in services:
        factories.append(STATIC_SERVICE_MAPPING[service])

    if not factories:
        raise Exception('No services to start.')

    try:
        forseti_config = file_loader.read_and_parse_file(
            forseti_config_file_path)
    except (AttributeError, IOError) as err:
        LOGGER.error('Unable to open Forseti Security config file. '
                     'Please check your path and filename and try '
                     'again. Error: %s', err)

    # Setting up configurations
    forseti_inventory_config = forseti_config.get('inventory', {})
    inventory_config = InventoryConfig(
        forseti_inventory_config.get('root_resource_id', ''),
        forseti_inventory_config.get('gsuite_service_account_key_file', ''),
        forseti_inventory_config.get('domain_super_admin_email', ''),
        forseti_inventory_config.get('api_quota', {}))

    # TODO: Create Config classes to store scanner and notifier configs.
    forseti_scanner_config = forseti_config.get('scanner', {})

    forseti_notifier_config = forseti_config.get('notifier', {})

    forseti_global_config = forseti_config.get('global', {})

    config = ServiceConfig(inventory_config=inventory_config,
                           scanner_config=forseti_scanner_config,
                           notifier_config=forseti_notifier_config,
                           global_config=forseti_global_config,
                           forseti_db_connect_string=forseti_db_connect_string,
                           endpoint=endpoint,
                           enable_debug_mode=enable_debug_mode)

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
        help='Path to Forseti configuration file.')
    parser.add_argument(
        '--services',
        nargs='*',
        default=[],
        help='Forseti services')
    parser.add_argument(
        '--log_level',
        default='info',
        choices=['debug', 'info', 'warning', 'error'],
        help='Sets the threshold for Forseti\'s logger.'
             ' Logging messages which are less severe'
             ' than the level you set will be ignored.')
    parser.add_argument(
        '--enable_console_log',
        action='store_true',
        help='Print log to console.')
    parser.add_argument(
        '--enable_debug_mode',
        action='store_true',
        help='Emit additional details for debugging.')
    args = vars(parser.parse_args())

    serve(args['endpoint'],
          args['services'],
          args['forseti_db'],
          args['forseti_config_file_path'],
          args['log_level'],
          args['enable_console_log'],
          args['enable_debug_mode'])


if __name__ == '__main__':
    main()
