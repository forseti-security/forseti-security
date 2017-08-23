# Copyright 2017 Google Inc.
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

""" Inventory gRPC service. """

import google.protobuf.timestamp_pb2 as timestamp

from google.cloud.security.iam.inventory import inventory_pb2
from google.cloud.security.iam.inventory import inventory_pb2_grpc
from google.cloud.security.iam.inventory import inventory

# TODO: The next editor must remove this disable and correct issues.
# pylint: disable=missing-type-doc,missing-return-type-doc,missing-return-doc
# pylint: disable=missing-param-doc


def inventory_pb_from_object(inventory_index):
    """Convert internal inventory datastructure to protobuf."""

    return inventory_pb2.InventoryIndex(
        id=inventory_index.id,
        start_time=timestamp.Timestamp().FromDatetime(
            inventory_index.start_time),
        complete_time=timestamp.Timestamp().FromDatetime(
            inventory_index.complete_time),
        schema_version=inventory_index.schema_version,
        count_objects=inventory_index.counter,
        status=inventory_index.status,
        warnings=inventory_index.warnings,
        errors=inventory_index.errors)


class GrpcInventory(inventory_pb2_grpc.InventoryServicer):
    """Inventory gRPC handler."""

    def __init__(self, inventory_api):
        super(GrpcInventory, self).__init__()
        self.inventory = inventory_api

    def Ping(self, request, _):
        """Ping implemented to check service availability.

        Args:
            request (object): gRPC request object.
            _ (object): Unused.

        Returns:
            object: PingReply containing echo of data.
        """

        return inventory_pb2.PingReply(data=request.data)

    def Create(self, request, _):
        """Creates a new inventory.

        Args:
            request (object): gRPC request object.
            _ (object): Unused.

        Yields:
            object: Inventory progress updates.
        """

        for progress in self.inventory.Create(request.background,
                                              request.model_name):
            yield inventory_pb2.Progress(
                id=progress.inventory_id,
                final_message=progress.final_message,
                step=progress.step,
                warnings=progress.warnings,
                errors=progress.errors,
                last_warning=repr(progress.last_warning),
                last_error=repr(progress.last_error))

    def List(self, request, _):
        """Lists existing inventory.

        Args:
            request (object): gRPC request object.
            _ (object): Unused.

        Yields:
            object: Each Inventory API object.
        """

        for inventory_index in self.inventory.List():
            yield inventory_pb_from_object(inventory_index)

    def Get(self, request, _):
        """Gets existing inventory.

        Args:
            request (object): gRPC request object.
            _ (object): Unused.

        Returns:
            object: Inventory API object that is requested.
        """

        inventory_index = self.inventory.Get(request.id)
        return inventory_pb2.GetReply(
            inventory=inventory_pb_from_object(inventory_index))

    def Delete(self, request, _):
        """Deletes existing inventory.

        Returns:
            request (object): gRPC request object.
            _ (object): Unused

        Returns:
            object: Inventory API object that is deleted.
        """

        inventory_index = self.inventory.Delete(request.id)
        return inventory_pb2.DeleteReply(
            inventory=inventory_pb_from_object(inventory_index))


class GrpcInventoryFactory(object):
    """Factory class for Inventory service gRPC interface"""

    def __init__(self, config):
        self.config = config

    def create_and_register_service(self, server):
        """Creates an inventory service and registers it in the server.

        Args:
            server (object): Server to register service to.

        Returns:
            object: The instantiated gRPC service for inventory.
        """

        service = GrpcInventory(
            inventory_api=inventory.Inventory(
                self.config))
        inventory_pb2_grpc.add_InventoryServicer_to_server(service, server)
        return service
