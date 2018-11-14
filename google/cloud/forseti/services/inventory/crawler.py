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


import threading
import time
from Queue import Empty, Queue

from google.cloud.forseti.common.util import logger
from google.cloud.forseti.services.inventory.base import crawler
from google.cloud.forseti.services.inventory.base import gcp
from google.cloud.forseti.services.inventory.base import resources

from google.cloud.forseti.common.opencensus import tracing

LOGGER = logger.get_logger(__name__)


class CrawlerConfig(crawler.CrawlerConfig):
    """Crawler configuration to inject dependencies."""

    def __init__(self, storage, progresser, api_client, tracer, variables=None):
        """Initialize

        Args:
            storage (Storage): The inventory storage
            progresser (QueueProgresser): The progresser implemented using
                a queue
            api_client (ApiClientImpl): GCP API client
            tracer (~opencensus.trace.tracer.Tracer): OpenCensus tracer object
            variables (dict): config variables
        """
        super(CrawlerConfig, self).__init__()
        self.storage = storage
        self.progresser = progresser
        self.tracer = tracer
        self.variables = {} if not variables else variables
        self.client = api_client


class ParallelCrawlerConfig(crawler.CrawlerConfig):
    """Multithreaded crawler configuration, to inject dependencies."""

    def __init__(self, storage, progresser, api_client, tracer, threads=10,
                 variables=None):
        """Initialize

        Args:
            storage (Storage): The inventory storage
            progresser (QueueProgresser): The progresser implemented using
                a queue
            api_client (ApiClientImpl): GCP API client
            tracer (~opencensus.trace.tracer.Tracer): OpenCensus tracer object
            threads (int): how many threads to use
            variables (dict): config variables
        """
        super(ParallelCrawlerConfig, self).__init__()
        self.storage = storage
        self.progresser = progresser
        self.tracer = tracer
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

    @tracing.trace(lambda x: x.config.tracer)
    def visit(self, resource):
        """Handle a newly found resource.

        Args:
            resource (object): Resource to handle.

        Raises:
            Exception: Reraises any exception.
        """
        attrs = {
            'id': resource._data['name'],
            'parent': resource._data.get('parent', None),
            'type': resource.__class__.__name__,
            'success': True
        }
        progresser = self.config.progresser
        try:

            resource.get_iam_policy(self.get_client())
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
            attrs['exception'] = e
            attrs['success'] = False
            raise
        else:
            progresser.on_new_object(resource)
        #finally:
            #tracing.end_span(self.config.tracer, **attrs)

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

    def on_child_error(self, error):
        """Process the error generated by child of a resource

           Inventory does not stop for children errors but raise a warning

        Args:
            error (str): error message to handle
        """

        warning_message = '{}\n'.format(error)
        self.config.storage.warning(warning_message)
        self.config.progresser.on_warning(error)

    @tracing.trace(lambda x: x.config.tracer)
    def update(self, resource):
        """Update the row of an existing resource

        Args:
            resource (Resource): Resource to update.

        Raises:
            Exception: Reraises any exception.
        """

        try:
            self.config.storage.update(resource)
        except Exception as e:
            LOGGER.exception(e)
            self.config.progresser.on_error(e)
            raise


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
        for _ in xrange(self.config.threads):
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

    def write(self, resource):
        """Save resource to storage.

        Args:
            resource (Resource): Resource to handle.
        """
        with self._write_lock:
            self.config.storage.write(resource)

    def on_child_error(self, error):
        """Process the error generated by child of a resource

           Inventory does not stop for children errors but raise a warning

        Args:
            error (str): error message to handle
        """

        warning_message = '{}\n'.format(error)
        with self._write_lock:
            self.config.storage.warning(warning_message)

        self.config.progresser.on_warning(error)

    def update(self, resource):
        """Update the row of an existing resource

        Args:
            resource (Resource): The db row of Resource to update

        Raises:
            Exception: Reraises any exception.
        """

        try:
            with self._write_lock:
                self.config.storage.update(resource)
        except Exception as e:
            LOGGER.exception(e)
            self.config.progresser.on_error(e)
            raise

def run_crawler(storage,
                progresser,
                config,
                parallel=True):
    """Run the crawler with a determined configuration.

    Args:
        storage (object): Storage implementation to use.
        progresser (object): Progresser to notify status updates.
        config (object): Inventory configuration on server
        parallel (bool): If true, use the parallel crawler implementation.

    Returns:
        QueueProgresser: The progresser implemented in inventory
    """
    tracer = config.service_config.tracer
    LOGGER.info(tracer.span_context)
    tracing.start_span(tracer, 'inventory', 'run_crawler')
    client_config = config.get_api_quota_configs()
    client_config['domain_super_admin_email'] = config.get_gsuite_admin_email()

    root_id = config.get_root_resource_id()
    client = gcp.ApiClientImpl(client_config)
    resource = resources.from_root_id(client, root_id)
    if parallel:
        crawler_config = ParallelCrawlerConfig(storage,
                                               progresser,
                                               client,
                                               tracer)
        crawler_impl = ParallelCrawler(crawler_config)
    else:
        crawler_config = CrawlerConfig(storage, progresser, client, tracer)
        crawler_impl = Crawler(crawler_config)
    progresser = crawler_impl.run(resource)
    # flush the buffer at the end to make sure nothing is cached.
    storage.commit()
    tracing.end_span(tracer, **progresser.__dict__)
    return progresser
