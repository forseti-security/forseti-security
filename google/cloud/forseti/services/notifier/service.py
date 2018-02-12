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

"""Notifier gRPC service. """

from google.cloud.forseti.notifier import notifier
from google.cloud.forseti.services.notifier import notifier_pb2
from google.cloud.forseti.services.notifier import notifier_pb2_grpc
from google.cloud.forseti.common.util import log_util

LOGGER = log_util.get_logger(__name__)

# TODO: The next editor must remove this disable and correct issues.
# pylint: disable=missing-type-doc,missing-return-type-doc,missing-return-doc
# pylint: disable=missing-param-doc


class GrpcNotifier(notifier_pb2_grpc.NotifierServicer):
    """Notifier gRPC implementation."""

    HANDLE_KEY = "handle"

    def _get_handle(self, context):
        """Return the handle associated with the gRPC call."""

        metadata = context.invocation_metadata()
        metadata_dict = {}
        for key, value in metadata:
            metadata_dict[key] = value
        return metadata_dict[self.HANDLE_KEY]

    def __init__(self, notifier_api, service_config):
        super(GrpcNotifier, self).__init__()
        self.notifier = notifier_api
        self.service_config = service_config

    def Ping(self, request, _):
        """Provides the capability to check for service availability."""

        return notifier_pb2.PingReply(data=request.data)

    def Run(self, request, context):
        """Run notifier."""

        LOGGER.info('Run notifier service with inventory index id: %s',
                    request.inventory_index_id)
        result = self.notifier.run(
            request.inventory_index_id,
            self.service_config)

        reply = notifier_pb2.RunReply()
        reply.status = result
        return reply


class GrpcNotifierFactory(object):
    """Factory class for Notifier service gRPC interface"""

    def __init__(self, config):
        self.config = config

    def create_and_register_service(self, server):
        """Create and register the Notifier service."""
        service = GrpcNotifier(notifier_api=notifier,
                               service_config=self.config)
        notifier_pb2_grpc.add_NotifierServicer_to_server(service, server)
        LOGGER.info("service %s created and registered", service)
        return service
