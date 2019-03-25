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

"""Server Config gRPC service. """

import json
import logging

from google.cloud.forseti.services.server_config import server_pb2
from google.cloud.forseti.services.server_config import server_pb2_grpc
from google.cloud.forseti.common.util import logger


LOGGER = logger.get_logger(__name__)


class GrpcServiceConfig(server_pb2_grpc.ServerServicer):
    """Service Config gRPC implementation."""

    def __init__(self, service_config):
        """Init.

        Args:
            service_config (ServiceConfig): Forseti server configs.
        """
        self.service_config = service_config

    def Ping(self, request, _):
        """Provides the capability to check for service availability.

        Args:
            request (PingRequest): The ping request.
            _ (object): Context of the request.

        Returns:
            PingReply: The response to the ping request.
        """

        return server_pb2.PingReply(data=request.data)

    def GetLogLevel(self, request, _):
        """Get Log level.

        Args:
            request (PingRequest): The ping request.
            _ (object): Context of the request.

        Returns:
            GetLogLevelReply: The GetLogLevelReply grpc object.
        """
        del request

        log_level = logging.getLevelName(LOGGER.getEffectiveLevel())

        LOGGER.info('Retrieving log level, log_level = %s',
                    log_level)

        return server_pb2.GetLogLevelReply(log_level=log_level)

    def SetLogLevel(self, request, _):
        """Set log level.

        Args:
            request (SetLogLevelRequest): The grpc request object.
            _ (object): Context of the request.

        Returns:
            SetLogLevelReply: The SetLogLevelReply grpc object.
        """
        err_msg = ''

        try:
            LOGGER.info('Setting log level, log_level = %s',
                        request.log_level)
            logger.set_logger_level(logger.LOGLEVELS[request.log_level])
        except Exception as e:  # pylint: disable=broad-except
            LOGGER.exception(e)
            err_msg = e.message

        is_success = not err_msg

        return server_pb2.SetLogLevelReply(is_success=is_success,
                                           error_message=err_msg)

    def ReloadServerConfiguration(self, request, _):
        """Reload Server Configuration.

        Args:
            request (ReloadServerConfigurationRequest): The grpc request
                object.
            _ (object): Context of the request.

        Returns:
            ReloadServerConfigurationReply: The ReloadConfigurationReply
                grpc object.
        """

        LOGGER.info('Reloading server configurations')
        is_success, err_msg = self.service_config.update_configuration(
            request.config_file_path)

        return server_pb2.ReloadServerConfigurationReply(
            is_success=is_success,
            error_message=err_msg)

    def GetServerConfiguration(self, request, _):
        """Get Server Configuration.

        Args:
            request (GetServerConfigurationRequest): The grpc request object.
            _ (object): Context of the request.

        Returns:
            GetServerConfigurationReply: The ReloadConfigurationReply
                grpc object.
        """

        LOGGER.info('Getting server configurations')
        forseti_config = self.service_config.get_forseti_config()

        return server_pb2.GetServerConfigurationReply(
            configuration=json.dumps(forseti_config, sort_keys=True))


class GrpcServerConfigFactory(object):
    """Factory class for Server config service gRPC interface"""

    def __init__(self, config):
        """Init.

        Args:
            config (ServiceConfig): The service config.
        """
        self.config = config

    def create_and_register_service(self, server):
        """Create and register the Service Config service.

        Args:
            server (object): The server object.

        Returns:
             object: The service object.
        """
        service = GrpcServiceConfig(service_config=self.config)
        server_pb2_grpc.add_ServerServicer_to_server(service, server)
        LOGGER.info('Service %s created and registered', service)
        return service
