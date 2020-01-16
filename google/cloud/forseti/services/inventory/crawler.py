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

"""Crawler implementation."""

from builtins import str
from builtins import range
from queue import Empty
from queue import Queue
import threading
import time

from future import standard_library
from google.cloud.forseti.common.util import logger
from google.cloud.forseti.services.inventory import cai_temporary_storage
from google.cloud.forseti.services.inventory.base import cai_gcp_client
from google.cloud.forseti.services.inventory.base import cloudasset
from google.cloud.forseti.services.inventory.base import crawler
from google.cloud.forseti.services.inventory.base import gcp
from google.cloud.forseti.services.inventory.base import resources

standard_library.install_aliases()

LOGGER = logger.get_logger(__name__)


class CrawlerConfig(crawler.CrawlerConfig):
    """Crawler configuration to inject dependencies."""

    def __init__(self, storage, progresser, api_client, variables=None):
        """Initialize

        Args:
            storage (Storage): The inventory storage
            progresser (QueueProgresser): The progresser implemented using
                a queue
            api_client (ApiClientImpl): GCP API client
            variables (dict): config variables
        """
        super(CrawlerConfig, self).__init__()
        self.storage = storage
        self.progresser = progresser
        self.variables = {} if not variables else variables
        self.client = api_client


class ParallelCrawlerConfig(crawler.CrawlerConfig):
    """Multithreaded crawler configuration, to inject dependencies."""

    def __init__(self, storage, progresser, api_client, threads,
                 variables=None):
        """Initialize

        Args:
            storage (Storage): The inventory storage
            progresser (QueueProgresser): The progresser implemented using
                a queue
            api_client (ApiClientImpl): GCP API client
            threads (int): how many threads to use
            variables (dict): config variables
        """
        super(ParallelCrawlerConfig, self).__init__()
        self.storage = storage
        self.progresser = progresser
        self.variables = {} if not variables else variables
        self.threads = threads
        self.client = api_client


class Crawler(crawler.Crawler):
    """Simple single-threaded Crawler implementation."""

    def __init__(self, config):
        """Initialize

        Args:
            config (CrawlerConfig): The crawler configuration
        """
        super(Crawler, self).__init__()
        self.config = config

    def run(self, resource):
        """Run the crawler, given a start resource.

        Args:
            resource (object): Resource to start with.

        Returns:
            QueueProgresser: The filled progresser described in inventory
        """

        resource.accept(self)
        return self.config.progresser

    def visit(self, resource):
        """Handle a newly found resource.

        Args:
            resource (object): Resource to handle.

        Raises:
            Exception: Reraises any exception.
        """

        progresser = self.config.progresser
        try:

            resource.get_iam_policy(self.get_client())
            resource.get_org_policy(self.get_client())
            resource.get_access_policy(self.get_client())
            resource.get_gcs_policy(self.get_client())
            resource.get_dataset_policy(self.get_client())
            resource.get_cloudsql_policy(self.get_client())
            resource.get_billing_info(self.get_client())
            resource.get_enabled_apis(self.get_client())
            resource.get_kubernetes_service_config(self.get_client())

            self.write(resource)
        except Exception as e:
            LOGGER.exception(e)
            progresser.on_error(e)
            raise
        else:
            progresser.on_new_object(resource)

    def dispatch(self, callback):
        """Dispatch crawling of a subtree.

        Args:
            callback (function): Callback to dispatch.
        """
        callback()

    def write(self, resource):
        """Save resource to storage.

        Args:
            resource (object): Resource to handle.
        """
        self.config.storage.write(resource)

    def get_client(self):
        """Get the GCP API client.

        Returns:
            object: GCP API client
        """

        return self.config.client

    def on_child_error(self, resource_full_name, error):
        """Process the error generated by child of a resource

           Inventory does not stop for children errors but raise a warning

        Args:
            resource_full_name (str): The full name of the resource that raised
                the error.
            error (str): error message to handle
        """

        self.config.storage.warning(resource_full_name, error)
        self.config.progresser.on_warning(error)


class ParallelCrawler(Crawler):
    """Multi-threaded Crawler implementation."""

    def __init__(self, config):
        """Initialize

        Args:
            config (ParallelCrawlerConfig): The crawler configuration
        """
        super(ParallelCrawler, self).__init__(config)
        self._write_lock = threading.Lock()
        self._dispatch_queue = Queue()
        self._shutdown_event = threading.Event()

    def _start_workers(self):
        """Start a pool of worker threads for processing the dispatch queue."""
        self._shutdown_event.clear()
        for _ in range(self.config.threads):
            worker = threading.Thread(target=self._process_queue)
            worker.daemon = True
            worker.start()

    def _process_queue(self):
        """Process items in the queue until the shutdown event is set."""
        while not self._shutdown_event.is_set():
            try:
                callback = self._dispatch_queue.get(timeout=1)
            except Empty:
                continue

            callback()
            self._dispatch_queue.task_done()

    def run(self, resource):
        """Run the crawler, given a start resource.

        Args:
            resource (Resource): Resource to start with.

        Returns:
            QueueProgresser: The filled progresser described in inventory
        """
        try:
            self._start_workers()
            resource.accept(self)
            self._dispatch_queue.join()
        finally:
            self._shutdown_event.set()
            # Wait for threads to exit.
            time.sleep(2)
        return self.config.progresser

    def dispatch(self, callback):
        """Dispatch crawling of a subtree.

        Args:
            callback (function): Callback to dispatch.
        """
        self._dispatch_queue.put(callback)


def _api_client_factory(config, threads, inventory_index_id):
    """Creates the proper initialized API client based on the configuration.

    Args:
        config (object): Inventory configuration on server.
        threads (int): how many threads to use.
        inventory_index_id (int): The inventory index ID for this export.

    Returns:
        Union[gcp.ApiClientImpl, cai_gcp_client.CaiApiClientImpl]:
            The initialized api client implementation class.
    """
    client_config = config.get_api_quota_configs()
    client_config['domain_super_admin_email'] = config.get_gsuite_admin_email()
    client_config['excluded_resources'] = config.get_excluded_resources()
    if config.get_cai_enabled():
        # TODO: When CAI supports resource exclusion, update the following
        #       method to handle resource exclusion during export time.
        engine, tmpfile = cai_temporary_storage.create_sqlite_db(threads)
        asset_count = cloudasset.load_cloudasset_data(
            engine,
            config,
            inventory_index_id)
        LOGGER.info('%s total assets loaded from Cloud Asset data.',
                    asset_count)

        if asset_count:
            return cai_gcp_client.CaiApiClientImpl(client_config,
                                                   engine,
                                                   tmpfile)

    # Default to the non-CAI implementation
    return gcp.ApiClientImpl(client_config)


def _crawler_factory(storage, progresser, client, parallel, threads):
    """Creates the proper initialized crawler based on the configuration.

    Args:
        storage (object): Storage implementation to use.
        progresser (object): Progresser to notify status updates.
        client (object): The API client instance.
        parallel (bool): If true, use the parallel crawler implementation.
        threads (int): how many threads to use when running in parallel

    Returns:
        Union[Crawler, ParallelCrawler]:
            The initialized crawler implementation class.
    """
    excluded_resources = set(client.config.get('excluded_resources', []))
    config_variables = {'excluded_resources': excluded_resources}
    if parallel:
        parallel_config = ParallelCrawlerConfig(storage,
                                                progresser,
                                                client,
                                                threads=threads,
                                                variables=config_variables)
        return ParallelCrawler(parallel_config)

    # Default to the non-parallel crawler
    crawler_config = CrawlerConfig(storage,
                                   progresser,
                                   client,
                                   variables=config_variables)
    return Crawler(crawler_config)


def _root_resource_factory(config, client):
    """Creates the proper initialized crawler based on the configuration.

    Args:
        config (object): Inventory configuration on server.
        client (object): The API client instance.

    Returns:
        Resource: The initialized root resource.
    """
    if config.use_composite_root():
        composite_root_resources = config.get_composite_root_resources()
        return resources.CompositeRootResource.create(composite_root_resources)

    # Default is a single resource as root.
    return resources.from_root_id(client, config.get_root_resource_id())


def run_crawler(storage,
                progresser,
                config,
                parallel=True,
                threads=10):
    """Run the crawler with a determined configuration.

    Args:
        storage (object): Storage implementation to use.
        progresser (object): Progresser to notify status updates.
        config (object): Inventory configuration on server.
        parallel (bool): If true, use the parallel crawler implementation.
        threads (int): how many threads to use when running in parallel.

    Returns:
        QueueProgresser: The progresser implemented in inventory
    """
    if parallel and 'sqlite' in str(config.get_service_config().get_engine()):
        LOGGER.info('SQLite used, disabling parallel threads.')
        parallel = False
        threads = 1

    client = _api_client_factory(
        config, threads, progresser.inventory_index_id)
    crawler_impl = _crawler_factory(storage, progresser, client, parallel,
                                    threads)
    resource = _root_resource_factory(config, client)

    progresser = crawler_impl.run(resource)
    return progresser
