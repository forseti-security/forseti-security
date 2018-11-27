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

""" Scanner gRPC service. """

from Queue import Queue

from google.cloud.forseti.common.util import logger
from google.cloud.forseti.scanner import scanner
from google.cloud.forseti.services.scanner.dao import initialize as init_storage
from google.cloud.forseti.services.scanner import scanner_pb2
from google.cloud.forseti.services.scanner import scanner_pb2_grpc

LOGGER = logger.get_logger(__name__)


class GrpcScanner(scanner_pb2_grpc.ScannerServicer):
    """IAM Scanner gRPC implementation."""

    HANDLE_KEY = 'handle'

    def _get_handle(self, context):
        """Return the handle associated with the gRPC call.

        Args:
            context (object): Context of the request.

        Returns:
            str: The model handle.
        """

        metadata = context.invocation_metadata()
        metadata_dict = {}
        for key, value in metadata:
            metadata_dict[key] = value
        return metadata_dict[self.HANDLE_KEY]

    def __init__(self, scanner_api, service_config):
        """Init.

        Args:
            scanner_api (Scanner): Scanner api implementation.
            service_config (ServiceConfig): Forseti 2.0 service configs.
        """
        super(GrpcScanner, self).__init__()
        self.scanner = scanner_api
        self.service_config = service_config
        LOGGER.info('initializing scanner DAO tables')
        init_storage(service_config.get_engine())

    def Ping(self, request, _):
        """Provides the capability to check for service availability.

        Args:
            request (PingRequest): The ping request.
            _ (object): Context of the request.

        Returns:
            PingReply: The response to the ping request.
        """

        return scanner_pb2.PingReply(data=request.data)

    def Run(self, _, context):
        """Run scanner.

        Args:
            _ (RunRequest): The run request.
            context (object): Context of the request.

        Yields:
            Progress: The progress of the scanner.
        """
        progress_queue = Queue()

        model_name = self._get_handle(context)
        if not model_name:
            progress_queue.put(
                'You must specify a model before running the Forseti'
                ' scanner. Run `forseti model -h` for more information.')
            progress_queue.put(None)
        else:
            LOGGER.info('Run scanner service with model: %s', model_name)
            self.service_config.run_in_background(
                lambda: self._run_scanner(model_name, progress_queue))

        for progress_message in iter(progress_queue.get, None):
            yield scanner_pb2.Progress(server_message=progress_message)

    def _run_scanner(self, model_name, progress_queue):
        """Run scanner.

        Args:
            model_name (str): Model name.
            progress_queue (Queue): Progress queue.
        """
        try:
            self.scanner.run(model_name,
                             progress_queue,
                             self.service_config)
        except Exception as e:  # pylint: disable=broad-except
            LOGGER.exception(e)
            progress_queue.put('Error occurred during the scanning process.')
            progress_queue.put(None)


class GrpcScannerFactory(object):
    """Factory class for Scanner service gRPC interface"""

    def __init__(self, config):
        """Init.

        Args:
            config (ServiceConfig): The service config.
        """
        self.config = config

    def create_and_register_service(self, server):
        """Create and register the IAM Scanner service.

        Args:
            server (object): The server object.

        Returns:
            object: The service object.
        """
        service = GrpcScanner(scanner_api=scanner,
                              service_config=self.config)
        scanner_pb2_grpc.add_ScannerServicer_to_server(service, server)
        LOGGER.info('Service %s created and registered.', service)
        return service
