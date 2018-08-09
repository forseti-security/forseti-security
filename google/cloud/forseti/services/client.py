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

"""Forseti gRPC client."""

import binascii
import os
import grpc

from google.cloud.forseti.services.explain import explain_pb2
from google.cloud.forseti.services.explain import explain_pb2_grpc
from google.cloud.forseti.services.inventory import inventory_pb2
from google.cloud.forseti.services.inventory import inventory_pb2_grpc
from google.cloud.forseti.services.model import model_pb2
from google.cloud.forseti.services.model import model_pb2_grpc
from google.cloud.forseti.services.notifier import notifier_pb2
from google.cloud.forseti.services.notifier import notifier_pb2_grpc
from google.cloud.forseti.services.scanner import scanner_pb2
from google.cloud.forseti.services.scanner import scanner_pb2_grpc
from google.cloud.forseti.services.server_config import server_pb2
from google.cloud.forseti.services.server_config import server_pb2_grpc
from google.cloud.forseti.services.utils import oneof


# pylint: disable=too-many-instance-attributes

class ModelNotSetError(Exception):
    """ModelNotSetError."""
    pass


def require_model(f):
    """Decorator to perform check that the model handle exists in the service.

    Args:
        f (func): The model handle should exists when executing function f

    Returns:
        wrapper: Function wrapper to perform model handle existence check.
    """

    def wrapper(*args, **kwargs):
        """Function wrapper to perform model handle existence check.

        Args:
            args: args to be passed to the function
            kwargs: kwargs to be passed to the function

        Returns:
            object: Results of executing f if model handle exists

        Raises:
            ModelNotSetError: Model handle not set
        """
        if args[0].config.handle():
            return f(*args, **kwargs)
        raise ModelNotSetError('API requires model to be set.')
    return wrapper


class ClientConfig(dict):
    """Provide access to client configuration data."""

    def handle(self):
        """Return currently active handle.

        Returns:
            str: The data model handle of client configuration.
        """
        return self['handle']


class ForsetiClient(object):
    """Client base class."""

    def __init__(self, config):
        """Initialize

        Args:
            config (ClientConfig): the client config object
        """
        self.config = config

    def metadata(self):
        """Create default metadata for gRPC call.

        Returns:
            list: the default metada for gRPC call
        """
        return [('handle', self.config.handle())]


class ScannerClient(ForsetiClient):
    """Scanner service allows the client to scan a model."""

    def __init__(self, config):
        """Initialize

        Args:
            config (ClientConfig): the client config object
        """
        super(ScannerClient, self).__init__(config)
        self.stub = scanner_pb2_grpc.ScannerStub(config['channel'])

    def is_available(self):
        """Checks if the 'Scanner' service is available by performing a ping.

        Returns:
            bool: whether the service is available
        """

        data = binascii.hexlify(os.urandom(16))
        echo = self.stub.Ping(scanner_pb2.PingRequest(data=data)).data
        return echo == data

    @require_model
    def run(self):
        """Runs the scanner

        Returns:
            proto: the returned proto message.
        """
        request = scanner_pb2.RunRequest()
        return self.stub.Run(request,
                             metadata=self.metadata())


class ServerConfigClient(ForsetiClient):
    """Allows the client to update the server configuration."""

    def __init__(self, config):
        """Initialize

        Args:
            config (ClientConfig): the client config object
        """
        super(ServerConfigClient, self).__init__(config)
        self.stub = server_pb2_grpc.ServerStub(config['channel'])

    def is_available(self):
        """Checks if the 'Server Config' service is available by
        performing a ping.

        Returns:
            bool: whether the service is available
        """

        data = binascii.hexlify(os.urandom(16))
        echo = self.stub.Ping(server_pb2.PingRequest(data=data)).data
        return echo == data

    def get_log_level(self):
        """Gets the current log level.

        Returns:
            proto: the returned proto message.
        """
        request = server_pb2.GetLogLevelRequest()
        return self.stub.GetLogLevel(request)

    def set_log_level(self, log_level):
        """Sets the log level.

        Args:
            log_level (str): The updated log level.

        Returns:
            proto: the returned proto message.
        """
        request = server_pb2.SetLogLevelRequest(log_level=log_level)
        return self.stub.SetLogLevel(request)

    def reload_server_configuration(self, config_file_path=None):
        """Reload the server configuration.

        Args:
            config_file_path (str): Forseti configuration file path.

        Returns:
            proto: the returned proto message.
        """
        request = server_pb2.ReloadServerConfigurationRequest(
            config_file_path=config_file_path)
        return self.stub.ReloadServerConfiguration(request)

    def get_server_configuration(self):
        """Get the server configuration.

        Returns:
            proto: the returned proto message.
        """
        request = server_pb2.GetServerConfigurationRequest()
        return self.stub.GetServerConfiguration(request)


class NotifierClient(ForsetiClient):
    """Notifier service allows the client to send violation notifications."""

    def __init__(self, config):
        """Initialize

        Args:
            config (ClientConfig): the client config object
        """
        super(NotifierClient, self).__init__(config)
        self.stub = notifier_pb2_grpc.NotifierStub(config['channel'])

    def is_available(self):
        """Checks if the 'Notifier' service is available by performing a ping.

        Returns:
            bool: whether the "Inventory" service is available
        """

        data = binascii.hexlify(os.urandom(16))
        echo = self.stub.Ping(notifier_pb2.PingRequest(data=data)).data
        return echo == data

    def run(self, inventory_index_id):
        """Runs the notifier.

        Args:
            inventory_index_id (int64): Inventory Index Id.

        Returns:
            proto: the returned proto message.
        """

        request = notifier_pb2.RunRequest(
            inventory_index_id=inventory_index_id)
        return self.stub.Run(request,
                             metadata=self.metadata())


class ModelClient(ForsetiClient):
    """Model service allows the client to create models from inventory.

    Model provides the following functionality:
       - Create a new model by importing from inventory or create an empty
       - List/Delete functionality on models
    """

    def __init__(self, config):
        """Initialize

        Args:
            config (ClientConfig): the client config object
        """
        super(ModelClient, self).__init__(config)
        self.stub = model_pb2_grpc.ModellerStub(config['channel'])

    def is_available(self):
        """Checks if the 'Model' service is available by performing a ping.

        Returns:
            bool: whether the "Inventory" service is available
        """

        data = binascii.hexlify(os.urandom(16))
        echo = self.stub.Ping(model_pb2.PingRequest(data=data)).data
        return echo == data

    def new_model(self, source, name, inventory_index_id=0, background=True):
        """Creates a new model, reply contains the handle.

        Args:
            source (str): the source to create the model, either EMPTY
                or INVENTORY.
            name (str): the name for the model.
            inventory_index_id (int64): the index id of the inventory to
                import from.
            background (bool): whether to run in background.

        Returns:
            proto: the returned proto message of creating model
        """

        return self.stub.CreateModel(
            model_pb2.CreateModelRequest(
                type=source,
                name=name,
                id=inventory_index_id,
                background=background))

    def list_models(self):
        """List existing models in the service.

        Returns:
            proto: the returned proto message of list_models
        """

        return self.stub.ListModel(model_pb2.ListModelRequest())

    def get_model(self, model):
        """Get the details of a model by name or handle.

        Args:
            model (str): the name or the handle for the data model to query

        Returns:
            proto: the returned proto message of get model
        """

        return self.stub.GetModel(
            model_pb2.GetModelRequest(
                identifier=model),
            metadata=self.metadata())

    def delete_model(self, model_name):
        """Delete a model, deletes all corresponding data.

        Args:
            model_name (str): the handle of the data model to delete

        Returns:
            proto: the returned proto message of deleting model
        """

        return self.stub.DeleteModel(
            model_pb2.DeleteModelRequest(
                handle=model_name),
            metadata=self.metadata())


class InventoryClient(ForsetiClient):
    """Inventory service allows the client to create GCP inventory.

    Inventory provides the following functionality:
       - Create a new inventory and optionally import it
       - Manage your inventory using List/Get/Delete
    """

    def __init__(self, config):
        """Initialize

        Args:
            config (ClientConfig): the client config object
        """
        super(InventoryClient, self).__init__(config)
        self.stub = inventory_pb2_grpc.InventoryStub(config['channel'])

    def is_available(self):
        """Checks if the 'Inventory' service is available by performing a ping.

        Returns:
            bool: whether the "Inventory" service is available
        """

        data = binascii.hexlify(os.urandom(16))
        echo = self.stub.Ping(inventory_pb2.PingRequest(data=data)).data
        return echo == data

    def create(self, background=False, import_as=None, enable_debug=False):
        """Creates a new inventory, with an optional import.

        Args:
            background (bool): whether to run in background
            import_as (str): the name of the data model to create after
                inventory is created
            enable_debug (bool): whether to emit additional information
                for debugging

        Returns:
            proto: the returned proto message of create inventory
        """

        request = inventory_pb2.CreateRequest(
            background=background,
            model_name=import_as,
            enable_debug=enable_debug)
        return self.stub.Create(request)

    def get(self, inventory_index_id):
        """Returns all information about a particular inventory.

        Args:
            inventory_index_id (int): the index id of the inventory to query.

        Returns:
            proto: the returned proto message of get inventory.
        """

        request = inventory_pb2.GetRequest(
            id=inventory_index_id)
        return self.stub.Get(request)

    def delete(self, inventory_index_id):
        """Delete an inventory.

        Args:
            inventory_index_id (int64): the index id of the inventory to delete.

        Returns:
            proto: the returned proto message of delete inventory.
        """

        request = inventory_pb2.DeleteRequest(
            id=inventory_index_id)
        return self.stub.Delete(request)

    def purge(self, retention_days):
        """Purge all inventory data older than the retention days.

        Args:
            retention_days (str): Days of inventory data to retain.

        Returns:
            proto: the returned proto message of purge inventory.
        """

        request = inventory_pb2.PurgeRequest(
            retention_days=retention_days)
        return self.stub.Purge(request)

    def list(self):
        """Lists all available inventory.

        Returns:
            proto: the returned proto message of list inventory
        """

        request = inventory_pb2.ListRequest()
        return self.stub.List(request)


class ExplainClient(ForsetiClient):
    """Explain service allows the client to reason about a model.

    Explain provides the following functionality:
       - List access by resource/member
       - Provide information on why a member has access
       - Provide recommendations on how to provide access
    """

    def __init__(self, config):
        """Initialize

        Args:
            config (ClientConfig): the client config object
        """
        super(ExplainClient, self).__init__(config)
        self.stub = explain_pb2_grpc.ExplainStub(config['channel'])

    def is_available(self):
        """Checks if the 'Explain' service is available by performing a ping.

        Returns:
            bool: whether the "Inventory" service is available
        """

        data = binascii.hexlify(os.urandom(16))
        return self.stub.Ping(explain_pb2.PingRequest(data=data)).data == data

    @require_model
    def list_resources(self, resource_name_prefix):
        """List resources by name prefix.

        Args:
            resource_name_prefix (str): the prefix of resource_name to query

        Returns:
            proto: the returned proto message of list_resources
        """

        return self.stub.ListResources(
            explain_pb2.ListResourcesRequest(
                prefix=resource_name_prefix),
            metadata=self.metadata())

    @require_model
    def list_members(self, member_name_prefix):
        """List members by prefix.

        Args:
            member_name_prefix (str): the prefix of member_name to query

        Returns:
            proto: the returned proto message of list_members
        """

        return self.stub.ListGroupMembers(
            explain_pb2.ListGroupMembersRequest(
                prefix=member_name_prefix),
            metadata=self.metadata())

    @require_model
    def list_roles(self, role_name_prefix):
        """List roles by prefix, can be empty.

        Args:
            role_name_prefix (str): the prefix of role_name to query

        Returns:
            proto: the returned proto message of list_roles
        """

        return self.stub.ListRoles(
            explain_pb2.ListRolesRequest(
                prefix=role_name_prefix),
            metadata=self.metadata())

    @require_model
    def get_iam_policy(self, full_resource_name):
        """Get the IAM policy from the resource.

        Args:
            full_resource_name (str): the resource to query iam_policy

        Returns:
            proto: the returned proto message of get_iam_policy
        """

        return self.stub.GetIamPolicy(
            explain_pb2.GetIamPolicyRequest(
                resource=full_resource_name),
            metadata=self.metadata()).policy

    @require_model
    def check_iam_policy(self, full_resource_name, permission_name,
                         member_name):
        """Check access via IAM policy.

        Args:
            full_resource_name (str): the resource to check iam_policy
            permission_name (str): the permission to check iam_policy
            member_name (str): the member to check iam_policy

        Returns:
            proto: the returned proto message of check_iam_policy
        """

        return self.stub.CheckIamPolicy(
            explain_pb2.CheckIamPolicyRequest(
                resource=full_resource_name,
                permission=permission_name,
                identity=member_name),
            metadata=self.metadata())

    @require_model
    def explain_denied(self, member_name, resource_names, roles=None,
                       permission_names=None):
        """List possibilities to grant access which is currently denied.

        Args:
            member_name (str): the member to explain denied
            resource_names (list): the resources to explain denied
            roles (list): the roles to explain denied, one of roles or
                permission_names should be not none
            permission_names (list): the permissions to explain denied,
                one of roles or permission_names should be not none

        Returns:
            proto: the returned proto message of explain_denied

        Raises:
            Exception: Either roles or permission names must be set
        """

        roles = [] if roles is None else roles
        permission_names = [] if permission_names is None else permission_names
        if not oneof(roles != [], permission_names != []):
            raise Exception('Either roles or permission names must be set')
        request = explain_pb2.ExplainDeniedRequest(
            member=member_name,
            resources=resource_names,
            roles=roles,
            permissions=permission_names)
        return self.stub.ExplainDenied(request, metadata=self.metadata())

    @require_model
    def explain_granted(self, member_name, resource_name, role=None,
                        permission=None):
        """Provide data on all possibilities on
           how a member has access to a resources.

        Args:
            member_name (str): the member to explain granted
            resource_name (str): the resource to explain granted
            role (str): the role to explain granted, one of role or permission
                should be not none
            permission (str): the permission to explain granted, one of role
                or permission should be not none

        Returns:
            proto: the returned proto message of explain_granted

        Raises:
            Exception: Either role or permission must be set
        """

        if not oneof(role is not None, permission is not None):
            raise Exception('Either role or permission name must be set')
        request = explain_pb2.ExplainGrantedRequest()
        if role is not None:
            request.role = role
        else:
            request.permission = permission
        request.resource = resource_name
        request.member = member_name
        return self.stub.ExplainGranted(request, metadata=self.metadata())

    @require_model
    def query_access_by_resources(self, resource_name, permission_names,
                                  expand_groups=False):
        """List members who have access to a given resource.

        Args:
            resource_name (str): the resource to query who have access to
            permission_names (list): the permissions to constrain the query
            expand_groups (bool): whether to expand group relations

        Returns:
            proto: the returned proto message of query_access_by_resources
        """

        request = explain_pb2.GetAccessByResourcesRequest(
            resource_name=resource_name,
            permission_names=permission_names,
            expand_groups=expand_groups)
        return self.stub.GetAccessByResources(
            request, metadata=self.metadata())

    @require_model
    def query_access_by_members(self, member_name, permission_names,
                                expand_resources=False):
        """List resources to which a set of members has access to.

        Args:
            member_name (str): the member to query what resources he/she
                               has access to
            permission_names (list): the permissions to constrain the query
            expand_resources (bool): whether to expand resource hierarchy

        Returns:
            proto: the returned proto message of query_access_by_members
        """

        request = explain_pb2.GetAccessByMembersRequest(
            member_name=member_name,
            permission_names=permission_names,
            expand_resources=expand_resources)
        return self.stub.GetAccessByMembers(request, metadata=self.metadata())

    @require_model
    def query_access_by_permissions(self,
                                    role_name,
                                    permission_name,
                                    expand_groups=False,
                                    expand_resources=False):
        """List (resource, member) tuples satisfying the authorization

        Args:
            role_name (str): Role name to query for.
            permission_name (str): Permission name to query for.
            expand_groups (bool): Whether or not to expand groups.
            expand_resources (bool): Whether or not to expand resources.

        Returns:
            object: Generator yielding access tuples.
        """

        request = explain_pb2.GetAccessByPermissionsRequest(
            role_name=role_name,
            permission_name=permission_name,
            expand_groups=expand_groups,
            expand_resources=expand_resources)
        return self.stub.GetAccessByPermissions(
            request,
            metadata=self.metadata())

    @require_model
    def query_permissions_by_roles(self, role_names=None, role_prefixes=None):
        """List all the permissions per given roles.

        Args:
            role_names (list): Role names to query for.
            role_prefixes (list): Role name prefixes to query for.

        Returns:
            proto: the returned proto message of query_permissions_by_roles
        """

        role_names = [] if role_names is None else role_names
        role_prefixes = [] if role_prefixes is None else role_prefixes
        request = explain_pb2.GetPermissionsByRolesRequest(
            role_names=role_names, role_prefixes=role_prefixes)
        return self.stub.GetPermissionsByRoles(
            request, metadata=self.metadata())


class ClientComposition(object):
    """Client composition class.

        Most convenient to use since it comprises the common use cases among
        the different services.
    """

    DEFAULT_ENDPOINT = 'localhost:50051'

    def __init__(self, endpoint=DEFAULT_ENDPOINT, ping=False):
        """Initialize

        Args:
            endpoint (str): the channel endpoint
            ping (bool): whether to ping to test if all services registered

        Raises:
            Exception: gRPC connected but services not registered
        """
        self.channel = grpc.insecure_channel(endpoint)
        self.config = ClientConfig({'channel': self.channel, 'handle': ''})

        self.explain = ExplainClient(self.config)
        self.inventory = InventoryClient(self.config)
        self.scanner = ScannerClient(self.config)
        self.notifier = NotifierClient(self.config)
        self.model = ModelClient(self.config)
        self.server_config = ServerConfigClient(self.config)
        self.clients = [self.explain,
                        self.inventory,
                        self.scanner,
                        self.notifier,
                        self.model,
                        self.server_config]

        if ping:
            if not all([c.is_available() for c in self.clients]):
                raise Exception('gRPC connected but services not registered')

    def new_model(self, source, name, inventory_index_id=0, background=False):
        """Create a new model from the specified source.

        Args:
            source (str): the source to create the model, either EMPTY
                or INVENTORY.
            name (str): the name for the model.
            inventory_index_id (int64): the index id of the inventory to
                import from.
            background (bool): whether to run in background.

        Returns:
            proto: the returned proto message of creating model
        """

        return self.model.new_model(source, name, inventory_index_id,
                                    background)

    def list_models(self):
        """List existing models.

        Returns:
            proto: the returned proto message of list_models
        """

        return self.model.list_models()

    def get_model(self, model):
        """Get the details of a model by name or handle

        Args:
            model (str): the name or the handle for the data model to query

        Returns:
            proto: the returned proto message of get model
        """

        return self.model.get_model(model)

    def switch_model(self, model_name):
        """Switch the client into using a model.

        Args:
            model_name (str): the handle of the data model to switch to
        """

        self.config['handle'] = model_name

    def delete_model(self, model_name):
        """Delete a model. Deletes all associated data.

        Args:
            model_name (str): the handle of the data model to delete

        Returns:
            proto: the returned proto message of deleting model
        """

        return self.model.delete_model(model_name)
