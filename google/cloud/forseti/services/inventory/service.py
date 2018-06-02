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

""" Inventory gRPC service. """

import google.protobuf.timestamp_pb2 as timestamp

from google.cloud.forseti.services.inventory import inventory_pb2
from google.cloud.forseti.services.inventory import inventory_pb2_grpc
from google.cloud.forseti.services.inventory import inventory
from google.cloud.forseti.services.utils import autoclose_stream

# pylint: disable=no-member


def inventory_pb_from_object(inventory_index):
    """Convert internal inventory data structure to protobuf.

    Args:
        inventory_index (object): InventoryIndex class in inventory storage

    Returns:
        object: proto message of InventoryIndex
    """

    # complete_timestamp is None before the inventory finished.
    complete_timestamp = None
    if inventory_index.completed_at_datetime:
        complete_timestamp = timestamp.Timestamp()
        complete_timestamp.FromDatetime(inventory_index.completed_at_datetime)

    start_timestamp = timestamp.Timestamp()
    start_timestamp.FromDatetime(inventory_index.created_at_datetime)

    return inventory_pb2.InventoryIndex(
        id=inventory_index.id,
        start_timestamp=start_timestamp,
        complete_timestamp=complete_timestamp,
        schema_version=inventory_index.schema_version,
        count_objects=inventory_index.counter,
        status=inventory_index.inventory_status,
        warnings=inventory_index.inventory_index_warnings,
        errors=inventory_index.inventory_index_errors)


class GrpcInventory(inventory_pb2_grpc.InventoryServicer):
    """Inventory gRPC handler."""

    def __init__(self, inventory_api):
        """Initialize

        Args:
            inventory_api (object): inventory library
        """
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

    @autoclose_stream
    def Create(self, request, _):
        """Creates a new inventory.

        Args:
            request (object): gRPC request object.
            _ (object): Unused.

        Yields:
            object: Inventory progress updates.
        """

        for progress in self.inventory.create(request.background,
                                              request.model_name):

            if request.enable_debug:
                last_warning = repr(progress.last_warning)
                last_error = repr(progress.last_error)
            else:
                last_warning = None
                last_error = None

            yield inventory_pb2.Progress(
                id=progress.inventory_index_id,
                final_message=progress.final_message,
                step=progress.step,
                warnings=progress.warnings,
                errors=progress.errors,
                last_warning=last_warning,
                last_error=last_error)

    @autoclose_stream
    def List(self, request, _):
        """Lists existing inventory.

        Args:
            request (object): gRPC request object.
            _ (object): Unused.

        Yields:
            object: Each Inventory API object.
        """

        for inventory_index in self.inventory.list():
            yield inventory_pb_from_object(inventory_index)

    def Get(self, request, _):
        """Gets existing inventory.

        Args:
            request (object): gRPC request object.
            _ (object): Unused.

        Returns:
            object: Inventory API object that is requested.
        """

        inventory_index = self.inventory.get(request.id)
        return inventory_pb2.GetReply(
            inventory=inventory_pb_from_object(inventory_index))

    def Delete(self, request, _):
        """Deletes existing inventory.

        Args:
            request (object): gRPC request object.
            _ (object): Unused

        Returns:
            object: Inventory API object that is deleted.
        """

        inventory_index = self.inventory.delete(request.id)
        return inventory_pb2.DeleteReply(
            inventory=inventory_pb_from_object(inventory_index))

    def Purge(self, request, _):
        """Purge desired inventory data.

        Args:
            request (object): gRPC request object.
            _ (object): Unused

        Returns:
            object: gRPC reply object.
        """

        result = self.inventory.purge(request.retention_days)

        return inventory_pb2.PurgeReply(
            result=result)


class GrpcInventoryFactory(object):
    """Factory class for Inventory service gRPC interface"""

    def __init__(self, config):
        """Initialize

        Args:
            config (object): ServiceConfig in server
        """
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
