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

""" Playground gRPC service. """

from google.cloud.security.iam.inventory import inventory_pb2
from google.cloud.security.iam.inventory import inventory_pb2_grpc
from google.cloud.security.iam.inventory import inventory


# TODO: The next editor must remove this disable and correct issues.
# pylint: disable=missing-type-doc,missing-return-type-doc,missing-return-doc
# pylint: disable=missing-param-doc

def inventory_pb_from_object(inventory_index):
    """Convert internal inventory datastructure to protobuf."""

    return inventory_pb2.InventoryIndex(
        id=inventory_index.get_id(),
        start_time=inventory_index.get_start_time(),
        completion_time=inventory_index.get_completion_time(),
        schema_version=inventory_index.get_schema_version(),
        count_objects=inventory_index.get_object_count(),
        status=inventory_index.get_status(),
        warnings=inventory_index.get_warnings(),
        errors=inventory_index.get_errors())


# pylint: disable=no-self-use
class GrpcInventory(inventory_pb2_grpc.InventoryServicer):
    """Inventory gRPC handler."""

    def __init__(self, inventory_api):
        super(GrpcInventory, self).__init__()
        self.inventory = inventory_api

    def Ping(self, request, _):
        """Ping implemented to check service availability."""

        return inventory_pb2.PingReply(data=request.data)

    def Create(self, request, context):
        """Creates a new inventory."""

        for progress in self.inventory.Create(request.background,
                                              request.model_name):
            yield inventory_pb2.Progress(
                final_message=progress.final_message,
                step=progress.step,
                warnings=progress.warnings,
                errors=progress.errors,
                last_warning=progress.last_warning,
                last_error=progress.last_error)

    def List(self, request, context):
        """Lists existing inventory."""

        for inventory_index in self.inventory.List():
            yield inventory_pb_from_object(inventory_index)

    def Get(self, request, context):
        """Gets existing inventory."""

        inventory_index = self.inventory.Get(request.id)
        return inventory_pb_from_object(inventory_index)

    def Delete(self, request, context):
        """Deletes existing inventory."""

        inventory_index = self.inventory.Delete(request.id)
        return inventory_pb_from_object(inventory_index)


class GrpcInventoryFactory(object):
    """Factory class for Inventory service gRPC interface"""

    def __init__(self, config):
        self.config = config

    def create_and_register_service(self, server):
        """Creates an inventory service and registers it in the server"""

        service = GrpcInventory(
            inventory_api=inventory.Inventory(
                self.config))
        inventory_pb2_grpc.add_InventoryServicer_to_server(service, server)
        return service
