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

import logging

from google.cloud.forseti.services.server_config import server_config_pb2
from google.cloud.forseti.services.server_config import server_config_pb2_grpc
from google.cloud.forseti.common.util import logger


LOGGER = logger.get_logger(__name__)


class GrpcServiceConfig(server_config_pb2_grpc.ServerConfigServicer):
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

        return server_config_pb2.PingReply(data=request.data)

    def GetLogLevel(self, *_):
        """Get Log level.

        Args:
            _ (tuple): Unused args.

        Returns:
            GetLogLevelReply: The GetLogLevelReply grpc object.
        """
        log_level = logging.getLevelName(LOGGER.getEffectiveLevel())

        LOGGER.info('Retrieving log level, log_level = %s',
                    log_level)

        return server_config_pb2.GetLogLevelReply(log_level=log_level)

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
        except Exception as e:
            err_msg = e.message

        success = not err_msg

        return server_config_pb2.SetLogLevelReply(success=success,
                                                  error_message=err_msg)

    def ReloadServerConfiguration(self, request, _):
        """Reload Server Configuration.

        Args:
            request (ReloadConfigurationRequest): The grpc request object.
            _ (object): Context of the request.

        Returns:
            ReloadConfigurationReply: The ReloadConfigurationReply grpc object.
        """

        LOGGER.info('Reloading server configurations')
        success, err_msg = self.service_config.update_configuration(
            request.config_file_path)

        return server_config_pb2.ReloadConfigurationReply(
            success=success,
            error_message=err_msg)


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
        server_config_pb2.add_ServerConfigServicer_to_server(service, server)
        LOGGER.info('Service %s created and registered', service)
        return service
