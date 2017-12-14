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

from google.cloud.forseti.scanner import scanner
from google.cloud.forseti.services.scanner import scanner_pb2
from google.cloud.forseti.services.scanner import scanner_pb2_grpc
from google.cloud.forseti.common.util import log_util


LOGGER = log_util.get_logger(__name__)

# TODO: The next editor must remove this disable and correct issues.
# pylint: disable=missing-type-doc,missing-return-type-doc,missing-return-doc
# pylint: disable=missing-param-doc


class GrpcScanner(scanner_pb2_grpc.ScannerServicer):
    """IAM Scanner gRPC implementation."""

    HANDLE_KEY = "handle"

    def _get_handle(self, context):
        """Return the handle associated with the gRPC call."""

        metadata = context.invocation_metadata()
        metadata_dict = {}
        for key, value in metadata:
            metadata_dict[key] = value
        return metadata_dict[self.HANDLE_KEY]

    def __init__(self, scanner_api, service_config):
        super(GrpcScanner, self).__init__()
        self.scanner = scanner_api
        self.service_config = service_config

    def Ping(self, request, _):
        """Provides the capability to check for service availability."""

        return scanner_pb2.PingReply(data=request.data)

    def Run(self, request, context):
        """Run scanner."""

        model_name = self._get_handle(context)
        LOGGER.info('Run scanner service with model: %s', model_name)
        result = self.scanner.run(request.config_dir, model_name,
                                  self.service_config)

        reply = scanner_pb2.RunReply()
        reply.status = result
        return reply


class GrpcScannerFactory(object):
    """Factory class for Scanner service gRPC interface"""

    def __init__(self, config):
        self.config = config

    def create_and_register_service(self, server):
        """Create and register the IAM Scanner service."""
        service = GrpcScanner(scanner_api=scanner,
                              service_config=self.config)
        scanner_pb2_grpc.add_ScannerServicer_to_server(service, server)
        return service
