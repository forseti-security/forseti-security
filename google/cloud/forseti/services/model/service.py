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
        """Return the handle associated with the gRPC call."""

        metadata = context.invocation_metadata()
        metadata_dict = {}
        for key, value in metadata:
            metadata_dict[key] = value
        return metadata_dict[self.HANDLE_KEY]

    def __init__(self, modeller_api):
        super(GrpcModeller, self).__init__()
        self.modeller = modeller_api

    def ping(self, request, _):
        """Provides the capability to check for service availability."""

        return model_pb2.PingReply(data=request.data)

    def create_model(self, request, context):
        """Creates a new model from an import source."""

        model = self.modeller.create_model(request.type,
                                           request.name,
                                           request.id,
                                           request.background)
        reply = model_pb2.CreateModelReply(model=model_pb2.Model(
            name=model.name,
            handle=model.handle,
            status=model.state,
            message=model.message))
        return reply

    def delete_model(self, request, _):
        """Deletes a model and all associated data."""

        model_name = request.handle
        self.modeller.delete_model(model_name)
        return model_pb2.DeleteModelReply()

    def list_model(self, request, _):
        """List all models."""

        models = self.modeller.list_model()
        models_pb = []
        for model in models:
            models_pb.append(model_pb2.Model(name=model.name,
                                             handle=model.handle,
                                             status=model.state,
                                             message=model.message,
                                             warnings=model.warnings))
        reply = model_pb2.ListModelReply()
        reply.models.extend(models_pb)
        return reply


class GrpcModellerFactory(object):
    """Factory class for model service gRPC interface"""

    def __init__(self, config):
        self.config = config

    def create_and_register_service(self, server):
        """Create and register the Model service."""

        service = GrpcModeller(modeller_api=modeller.Modeller(self.config))
        model_pb2_grpc.add_ModellerServicer_to_server(service, server)
        return service
