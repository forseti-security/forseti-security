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

"""Forseti Server model gRPC service."""

from google.cloud.forseti.common.util import string_formats
from google.cloud.forseti.services.model import model_pb2
from google.cloud.forseti.services.model import model_pb2_grpc
from google.cloud.forseti.services.model import modeller
from google.cloud.forseti.common.util import logger

LOGGER = logger.get_logger(__name__)


class GrpcModeller(model_pb2_grpc.ModellerServicer):
    """Modeller gRPC implementation."""

    HANDLE_KEY = 'handle'

    def _get_handle(self, context):
        """Return the handle associated with the gRPC call.

        Args:
            context (object): GRPC context

        Returns:
            str: handle of the GRPC call
        """

        metadata = context.invocation_metadata()
        metadata_dict = {}
        for key, value in metadata:
            metadata_dict[key] = value
        return metadata_dict[self.HANDLE_KEY]

    def __init__(self, modeller_api):
        """Initialize

        Args:
            modeller_api (object): model library
        """
        super(GrpcModeller, self).__init__()
        self.modeller = modeller_api

    def Ping(self, request, _):
        """Provides the capability to check for service availability.

        Args:
            request (object): pb2 object of PingRequest
            _(object): Not used

        Returns:
            object: pb2 object of the PingReply
        """

        return model_pb2.PingReply(data=request.data)

    def CreateModel(self, request, context):
        """Creates a new model from an import source.

        Args:
            request (object): pb2 object of CreateModelRequest
            context (object): gRPC context

        Returns:
            object: pb2 object of ModelSimplified
        """
        LOGGER.debug('Received request to create model: %s', request)
        model = self.modeller.create_model(request.type,
                                           request.name,
                                           request.id,
                                           request.background)
        created_at_str = self._get_model_created_at_str(model)
        LOGGER.debug('Model %s created at: %s', model, created_at_str)
        reply = model_pb2.CreateModelReply(model=model_pb2.ModelSimplified(
            name=model.name,
            handle=model.handle,
            status=model.state,
            createdAt=created_at_str,
            description=model.description))
        return reply

    def DeleteModel(self, request, _):
        """Deletes a model and all associated data.

        Args:
            request (object): pb2 object of DeleteModelRequest
            _ (object): Not used

        Returns:
            object: pb2 object of DeleteModelReply
        """

        # Protobuf enums are not handled correctly by the no-member check.
        # pylint: disable=no-member
        model_name = request.handle
        if not model_name:
            LOGGER.warn('No model name in request: %s', request)
            status = model_pb2.DeleteModelReply.FAIL
            return model_pb2.DeleteModelReply(status=status)

        try:
            self.modeller.delete_model(model_name)
            status = model_pb2.DeleteModelReply.SUCCESS
        except Exception:  # pylint: disable=broad-except
            LOGGER.exception('Unable to delete model: %s', model_name)
            status = model_pb2.DeleteModelReply.FAIL
        return model_pb2.DeleteModelReply(status=status)
        # pylint: enable=no-member

    def ListModel(self, request, _):
        """List all models.

        Args:
            request (object): pb2 object of ListModelRequest
            _ (object): Not used

        Yields:
            object: pb2 object of ModelSimplified
        """

        models = self.modeller.list_model()
        for model in models:
            created_at_str = self._get_model_created_at_str(model)
            yield model_pb2.ModelSimplified(name=model.name,
                                            handle=model.handle,
                                            status=model.state,
                                            createdAt=created_at_str,
                                            description=model.description,
                                            message=model.message)

    def GetModel(self, request, _):
        """Get details of a model.

        Args:
            request (object): pb2 object of GetModelRequest
            _ (object): Not used

        Returns:
            object: pb2 object of ModelDetails
        """

        model = self.modeller.get_model(request.identifier)
        if model:
            created_at_str = self._get_model_created_at_str(model)
            return model_pb2.ModelDetails(name=model.name,
                                          handle=model.handle,
                                          status=model.state,
                                          createdAt=created_at_str,
                                          description=model.description,
                                          message=model.message,
                                          warnings=model.warnings)
        return model_pb2.ModelDetails()

    @staticmethod
    def _get_model_created_at_str(model):
        """Get model created_at datetime in human readable string format.

        Args:
            model (Model): Model dao object.

        Return:
            str: created_at datetime in string format.
        """
        return model.created_at_datetime.strftime(
            string_formats.DEFAULT_FORSETI_HUMAN_TIMESTAMP)


class GrpcModellerFactory(object):
    """Factory class for model service gRPC interface"""

    def __init__(self, config):
        """Initialize

        Args:
            config (object): ServiceConfig in server
        """
        self.config = config

    def create_and_register_service(self, server):
        """Create and register the Model service.

        Args:
            server (object): Server to register service to.

        Returns:
            object: The instantiated gRPC service for model.
        """

        service = GrpcModeller(modeller_api=modeller.Modeller(self.config))
        model_pb2_grpc.add_ModellerServicer_to_server(service, server)
        LOGGER.info('Service %s created and registered', service)
        return service
