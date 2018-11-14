# Copyright 2018 The Forseti Security Authors. All rights reserved.
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

"""Base classes required for handling configuration of the gRPC server."""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import abc
from multiprocessing.pool import ThreadPool
import threading

from google.cloud.forseti.common.opencensus import tracing
from google.cloud.forseti.common.util import file_loader
from google.cloud.forseti.common.util import logger
from google.cloud.forseti.services import db
from google.cloud.forseti.services.client import ClientComposition
from google.cloud.forseti.services.dao import create_engine
from google.cloud.forseti.services.dao import ModelManager
from google.cloud.forseti.services.inventory.storage import Storage

LOGGER = logger.get_logger(__name__)


class AbstractInventoryConfig(dict):
    """Abstract base class for service configuration.

    This class is used to implement dependency injection for the gRPC
    services."""

    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def get_root_resource_id(self):
        """Returns the root resource id.

        Raises:
            NotImplementedError: Abstract.
        """
        raise NotImplementedError()

    @abc.abstractmethod
    def get_gsuite_admin_email(self):
        """Returns gsuite admin email.

        Raises:
            NotImplementedError: Abstract.
        """

        raise NotImplementedError()

    @abc.abstractmethod
    def get_api_quota_configs(self):
        """Returns the per API quota configs.

        Raises:
            NotImplementedError: Abstract.
        """
        raise NotImplementedError()

    @abc.abstractmethod
    def get_retention_days_configs(self):
        """Returns the days of inventory data to retain.

        Raises:
            NotImplementedError: Abstract.
        """
        raise NotImplementedError()

    @abc.abstractmethod
    def get_service_config(self):
        """Returns the service config.

        Raises:
            NotImplementedError: Abstract.
        """
        raise NotImplementedError()

    @abc.abstractmethod
    def set_service_config(self, service_config):
        """Attach a service configuration.

        Args:
            service_config (object): Service configuration.

        Raises:
            NotImplementedError: Abstract.
        """
        raise NotImplementedError()


class AbstractServiceConfig(object):
    """Abstract base class for service configuration.

    This class is used to implement dependency injection for the gRPC
    services."""

    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def get_engine(self):
        """Get the database engine.

        Raises:
            NotImplementedError: Abstract.
        """
        raise NotImplementedError()

    @abc.abstractmethod
    def scoped_session(self):
        """Get a scoped session.

        Raises:
            NotImplementedError: Abstract.
        """
        raise NotImplementedError()

    @abc.abstractmethod
    def client(self):
        """Get an API client.

        Raises:
            NotImplementedError: Abstract.
        """
        raise NotImplementedError()

    @abc.abstractmethod
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


class InventoryConfig(AbstractInventoryConfig):
    """Implements composed dependency injection for the inventory."""

    def __init__(self,
                 root_resource_id,
                 gsuite_admin_email,
                 api_quota_configs,
                 retention_days,
                 *args,
                 **kwargs):
        """Initialize.

        Args:
            root_resource_id (str): Root resource to start crawling from
            gsuite_admin_email (str): G Suite admin email
            api_quota_configs (dict): API quota configs
            retention_days (int): Days of inventory tables to retain
            *args: args when creating InventoryConfig
            **kwargs: kwargs when creating InventoryConfig
        """
        super(InventoryConfig, self).__init__(*args, **kwargs)
        self.service_config = None
        self.root_resource_id = root_resource_id
        self.gsuite_admin_email = gsuite_admin_email
        self.api_quota_configs = api_quota_configs
        self.retention_days = retention_days

    def get_root_resource_id(self):
        """Return the configured root resource id.

        Returns:
            str: Root resource id.
        """
        return self.root_resource_id

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

    def get_retention_days_configs(self):
        """Returns the days of inventory data to retain.

        Returns:
            int: The days of inventory data to retain.
        """
        return self.retention_days

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
                 forseti_config_file_path,
                 forseti_db_connect_string,
                 endpoint):
        """Initialize.

        Args:
            forseti_config_file_path (str): Path to Forseti configuration file
            forseti_db_connect_string (str): Forseti database string
            endpoint (str): server endpoint
        """

        super(ServiceConfig, self).__init__()
        self.thread_pool = ThreadPool()
        self.engine = create_engine(forseti_db_connect_string,
                                    pool_recycle=3600)
        self.model_manager = ModelManager(self.engine)
        self.sessionmaker = db.create_scoped_sessionmaker(self.engine)
        self.endpoint = endpoint

        self.forseti_config_file_path = forseti_config_file_path

        self.inventory_config = None
        self.scanner_config = None
        self.notifier_config = None
        self.global_config = None
        self.forseti_config = None
        self.tracer = None
        self.update_lock = threading.RLock()

    def init_tracer(self):
        """Fetch tracer from the interceptors and initialize it"""
        if tracing.OPENCENSUS_ENABLED:
            self.tracer = tracing.execution_context.get_opencensus_tracer()
            LOGGER.info(self.tracer.span_context)

    def _read_from_config(self, config_file_path=None):
        """Read from the forseti configuration file.

        Args:
            config_file_path (str): Forseti server config file path

        Returns:
            tuple(dict, str): (Forseti server configuration, Error message)
        """

        # if config_file_path is not passed in, we will use the default
        # configuration path that was passed in during the initialization
        # of the server.
        forseti_config_path = config_file_path or self.forseti_config_file_path

        forseti_config = {}

        err_msg = ''

        try:
            forseti_config = file_loader.read_and_parse_file(
                forseti_config_path)
        except (AttributeError, IOError):
            err_msg = ('Unable to open Forseti Security config file. Please '
                       'check your path and filename and try again.')
            LOGGER.exception(err_msg)

        return forseti_config, err_msg

    def update_configuration(self, config_file_path=None):
        """Update the inventory, scanner, global and notifier configurations.

        Args:
            config_file_path (str): Forseti server config file path.

        Returns:
            tuple(bool, str): (Configuration was updated, Error message)
        """

        forseti_config, err_msg = self._read_from_config(config_file_path)

        if not forseti_config:
            # if forseti_config is empty, there is nothing to update.
            return False, err_msg

        with self.update_lock:
            # Lock before performing the update to avoid multiple updates
            # at the same time.

            self.forseti_config = forseti_config

            # Setting up individual configurations
            forseti_inventory_config = forseti_config.get('inventory', {})
            inventory_config = InventoryConfig(
                forseti_inventory_config.get('root_resource_id', ''),
                forseti_inventory_config.get('domain_super_admin_email', ''),
                forseti_inventory_config.get('api_quota', {}),
                forseti_inventory_config.get('retention_days', -1))

            # TODO: Create Config classes to store scanner and notifier configs.
            forseti_scanner_config = forseti_config.get('scanner', {})

            forseti_notifier_config = forseti_config.get('notifier', {})

            forseti_global_config = forseti_config.get('global', {})

            self.inventory_config = inventory_config
            self.inventory_config.set_service_config(self)

            self.scanner_config = forseti_scanner_config
            self.notifier_config = forseti_notifier_config

            self.global_config = forseti_global_config
        return True, err_msg

    def get_forseti_config(self):
        """Get the Forseti config.

        Returns:
            dict: Forseti config.
        """

        return self.forseti_config

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
