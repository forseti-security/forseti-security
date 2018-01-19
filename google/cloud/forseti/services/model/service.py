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

from google.cloud.forseti.services.model import model_pb2
from google.cloud.forseti.services.model import model_pb2_grpc
from google.cloud.forseti.services.model import modeller


# TODO: The next editor must remove this disable and correct issues.
# pylint: disable=missing-type-doc,missing-return-type-doc,missing-return-doc
# pylint: disable=missing-param-doc


class GrpcModeller(model_pb2_grpc.ModellerServicer):
    """Modeller gRPC implementation."""

    HANDLE_KEY = "handle"

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
        super(GrpcModeller, self).__init__()
        self.modeller = modeller_api

    def Ping(self, request, _):
        """Provides the capability to check for service availability.

        Args:
            request (object): pb2 object of PingRequest

        Returns:
            object: pb2 object of the PingReply
        """

        return model_pb2.PingReply(data=request.data)

    def CreateModel(self, request, context):
        """Creates a new model from an import source.

        Args:
            request (object): pb2 object of CreateModelRequest

        Returns:
            object: pb2 object of ModelSimplified
        """

        model = self.modeller.CreateModel(request.type,
                                          request.name,
                                          request.id,
                                          request.background)
        reply = model_pb2.CreateModelReply(model=model_pb2.ModelSimplified(
            name=model.name,
            handle=model.handle,
            status=model.state,
            description=model.description))
        return reply

    def DeleteModel(self, request, _):
        """Deletes a model and all associated data.

        Args:
            request (object): pb2 object of DeleteModelRequest

        Returns:
            object: pb2 object of DeleteModelReply
        """

        model_name = request.handle
        self.modeller.DeleteModel(model_name)
        return model_pb2.DeleteModelReply()

    def ListModel(self, request, _):
        """List all models.

        Args:
            request (object): pb2 object of ListModelRequest

        Yields:
            object: pb2 object of ModelSimplified
        """

        models = self.modeller.ListModel()
        for model in models:
            yield model_pb2.ModelSimplified(name=model.name,
                                            handle=model.handle,
                                            status=model.state,
                                            description=model.description,
                                            message=model.message)

    def GetModel(self, request, _):
        """Get details of a model.

        Args:
            request (object): pb2 object of GetModelRequest

        Returns:
            object: pb2 object of ModelDetails
        """

        model = self.modeller.GetModel(request.identifier)

        if model:
            return model_pb2.ModelDetails(name=model.name,
                                          handle=model.handle,
                                          status=model.state,
                                          description=model.description,
                                          message=model.message,
                                          warnings=model.warnings)
        return model_pb2.ModelDetails()


class GrpcModellerFactory(object):
    """Factory class for model service gRPC interface"""

    def __init__(self, config):
        self.config = config

    def create_and_register_service(self, server):
        """Create and register the Model service."""

        service = GrpcModeller(modeller_api=modeller.Modeller(self.config))
        model_pb2_grpc.add_ModellerServicer_to_server(service, server)
        return service
