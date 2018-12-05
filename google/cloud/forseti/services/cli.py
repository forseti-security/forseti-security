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

"""Forseti CLI."""

from argparse import ArgumentParser
import json
import os
import sys

import grpc
from google.protobuf.json_format import MessageToJson

from google.cloud.forseti.services import client as iam_client
from google.cloud.forseti.services.client import ModelNotSetError
from google.cloud.forseti.common.util import file_loader
from google.cloud.forseti.common.util import logger


LOGGER = logger.get_logger(__name__)


# pylint: disable=too-many-lines

class DefaultParser(ArgumentParser):
    """Default parser, when error is triggered, instead of printing
    error message, it will print the help message (-h).
    """

    def error(self, message=None):
        """This method will be triggered when error occurred.

        Args:
            message (str): Error message.
        """
        if message:
            sys.stderr.write('Argument error: %s.\n' % message)
        self.print_usage()
        sys.exit(2)


def define_inventory_parser(parent):
    """Define the inventory service parser.

    Args:
        parent (argparser): Parent parser to hook into.
    """

    service_parser = parent.add_parser('inventory', help='inventory service')
    action_subparser = service_parser.add_subparsers(
        title='action',
        dest='action')

    create_inventory_parser = action_subparser.add_parser(
        'create',
        help='Start a new inventory')
    create_inventory_parser.add_argument(
        '--import_as',
        metavar=('MODEL_NAME',),
        help='Import the inventory when complete, requires a model name')
    create_inventory_parser.add_argument(
        '--background',
        '-b',
        action='store_true',
        help='Execute inventory in background',
    )
    create_inventory_parser.add_argument(
        '--enable_debug',
        action='store_true',
        help='Emit additional information for debugging.',
    )

    delete_inventory_parser = action_subparser.add_parser(
        'delete',
        help='Delete an inventory')
    delete_inventory_parser.add_argument(
        'id',
        help='Inventory id to delete')

    purge_inventory_parser = action_subparser.add_parser(
        'purge',
        help='Purge all inventory data older than the retention days.')
    purge_inventory_parser.add_argument(
        'retention_days',
        default=None,
        nargs='?',
        help=('Optional.  Number of days to retain the data. If not '
              'specified, then the value in forseti config yaml file will '
              'be used.'))

    _ = action_subparser.add_parser(
        'list',
        help='List all inventory')

    get_inventory_parser = action_subparser.add_parser(
        'get',
        help='Get a particular inventory')
    get_inventory_parser.add_argument(
        'id',
        help='Inventory id to get')


def define_config_parser(parent):
    """Define the config service parser.

    Args:
        parent (argparser): Parent parser to hook into.
    """

    service_parser = parent.add_parser(
        'config',
        help=('config service, persist and modify the'
              'client configuration in ~/.forseti'))

    action_subparser = service_parser.add_subparsers(
        title='action',
        dest='action')

    _ = action_subparser.add_parser(
        'show',
        help='Show the config')

    _ = action_subparser.add_parser(
        'reset',
        help='Reset the config to its default values')

    delete_config_parser = action_subparser.add_parser(
        'delete',
        help='Deletes an item from the config')
    delete_config_parser.add_argument(
        'key',
        type=str,
        help='Key to delete from config')

    set_endpoint_config_parser = action_subparser.add_parser(
        'endpoint',
        help='Configure the client endpoint')
    set_endpoint_config_parser.add_argument(
        'hostport',
        type=str,
        help='Server endpoint in host:port format')

    set_model_config_parser = action_subparser.add_parser(
        'model',
        help='Configure the model to use')
    set_model_config_parser.add_argument(
        'name',
        type=str,
        help='Handle of the model to use, as hexlified sha1sum')

    set_format_config_parser = action_subparser.add_parser(
        'format',
        help='Configure the output format')
    set_format_config_parser.add_argument(
        'name',
        choices=['json'],
        help='Configure the CLI output format')


def define_server_parser(parent):
    """Define the server config service parser.

    Args:
        parent (argparser): Parent parser to hook into.
    """

    service_parser = parent.add_parser(
        'server',
        help='Server config service')

    action_subparser = service_parser.add_subparsers(
        title='action',
        dest='action')

    log_level_parser = action_subparser.add_parser(
        'log_level',
        help='Log level of the server.')

    log_level_subparser = log_level_parser.add_subparsers(
        title='subaction',
        dest='subaction')

    set_log_level = log_level_subparser.add_parser(
        'set',
        help='Set the log level of the server.'
    )

    set_log_level.add_argument(
        'log_level',
        choices=['debug', 'info', 'warning', 'error'])

    _ = log_level_subparser.add_parser(
        'get',
        help='Get the log level of the server.')

    config_parser = action_subparser.add_parser(
        'configuration',
        help='Server configuration.')

    config_subparser = config_parser.add_subparsers(
        title='subaction',
        dest='subaction')

    _ = config_subparser.add_parser(
        'get',
        help='Get the server configuration.'
    )

    reload_config = config_subparser.add_parser(
        'reload',
        help='Load the server configuration.'
    )

    reload_config.add_argument(
        'config_file_path',
        nargs='?',
        type=str,
        help=('Forseti configuration file path. If not specified, '
              'the default path will be used. Note: Please specify '
              'a path that the server has access to (e.g. a path in '
              'the server vm or a gcs path starts with gs://).')
    )


def define_model_parser(parent):
    """Define the model service parser.

    Args:
        parent (argparser): Parent parser to hook into.
    """

    service_parser = parent.add_parser('model', help='model service')
    action_subparser = service_parser.add_subparsers(
        title='action',
        dest='action')

    use_model_parser = action_subparser.add_parser(
        'use',
        help='Context switch into the model.')
    use_model_parser.add_argument(
        'model',
        help='Model to switch to, either handle or name'
    )

    _ = action_subparser.add_parser(
        'list',
        help='List all available models')

    get_model_parser = action_subparser.add_parser(
        'get',
        help='Get the details of a model by name or handle')
    get_model_parser.add_argument(
        'model',
        help='Model to get')

    delete_model_parser = action_subparser.add_parser(
        'delete',
        help='Deletes an entire model')
    delete_model_parser.add_argument(
        'model',
        help='Model to delete, either handle or name')

    create_model_parser = action_subparser.add_parser(
        'create',
        help='Create a model')
    create_model_parser.add_argument(
        'name',
        help='Human readable name for this model')
    create_model_parser.add_argument(
        '--inventory_index_id',
        default='',
        help='Inventory id to import from'
    )
    create_model_parser.add_argument(
        '--background',
        '-b',
        default=False,
        action='store_true',
        help='Run import in background'
    )


def define_scanner_parser(parent):
    """Define the scanner service parser.

    Args:
        parent (argparser): Parent parser to hook into.
    """

    service_parser = parent.add_parser('scanner', help='scanner service')

    action_subparser = service_parser.add_subparsers(
        title='action',
        dest='action')

    run_scanner_parser = action_subparser.add_parser(
        'run',
        help='Run the scanner')

    run_scanner_parser.add_argument(
        '--scanner',
        choices=['external_project_access_scanner'],
        help='Run a specific scanner, '
             'currently only applicable for '
             'the external project access scanner'
    )


def define_notifier_parser(parent):
    """Define the notifier service parser.

    Args:
        parent (argparser): Parent parser to hook into.
    """

    service_parser = parent.add_parser('notifier', help='notifier service')

    action_subparser = service_parser.add_subparsers(
        title='action',
        dest='action')

    create_notifier_parser = action_subparser.add_parser(
        'run',
        help='Run the notifier')

    create_notifier_parser.add_argument(
        '--inventory_index_id',
        default=0,
        help=('Id of the inventory index to send violation notifications. '
              'If this is not specified, then the last inventory index id '
              'will be used.')
    )

    create_notifier_parser.add_argument(
        '--scanner_index_id',
        default=0,
        help=('Id of the scanner index to send violation notifications. '
              'If this is not specified, then the last scanner index id '
              'will be used.')
    )


# pylint: disable=too-many-locals
def define_explainer_parser(parent):
    """Define the explainer service parser.

    Args:
        parent (argparser): Parent parser to hook into.
    """

    service_parser = parent.add_parser('explainer', help='explain service')
    action_subparser = service_parser.add_subparsers(
        title='action',
        dest='action')

    list_resource_parser = action_subparser.add_parser(
        'list_resources',
        help='List resources')
    list_resource_parser.add_argument(
        '--prefix',
        default='',
        help='Resource full name prefix to filter for '
             '(e.g. organization/1234567890/folder/my-folder-id)')

    list_members_parser = action_subparser.add_parser(
        'list_members',
        help='List members by prefix')
    list_members_parser.add_argument(
        '--prefix',
        default='',
        help='Member prefix to filter for')

    list_roles_parser = action_subparser.add_parser(
        'list_roles',
        help='List roles by prefix')
    list_roles_parser.add_argument(
        '--prefix',
        default='',
        help='Role prefix to filter for')

    perms_by_roles_parser = action_subparser.add_parser(
        'list_permissions',
        help='List permissions by role(s)')
    perms_by_roles_parser.add_argument(
        '--roles',
        nargs='*',
        default=[],
        help='Role names')
    perms_by_roles_parser.add_argument(
        '--role_prefixes',
        nargs='*',
        default=[],
        help='Role prefixes')

    get_policy = action_subparser.add_parser(
        'get_policy',
        help='Get a resource\'s direct policy')
    get_policy.add_argument(
        'resource',
        help='Resource to get policy for')

    check_policy = action_subparser.add_parser(
        'check_policy',
        help='Check if a member has access to a resource')
    check_policy.add_argument(
        'resource',
        help='Resource to check on')
    check_policy.add_argument(
        'permission',
        help='Permissions to check on')
    check_policy.add_argument(
        'member',
        help='Member to check access for')

    explain_granted_parser = action_subparser.add_parser(
        'why_granted',
        help='Explain why a role or permission is'
             ' granted for a member on a resource')
    explain_granted_parser.add_argument(
        'member',
        help='Member to query')
    explain_granted_parser.add_argument(
        'resource',
        help='Resource to query')
    explain_granted_group = (
        explain_granted_parser.add_mutually_exclusive_group(required=True))
    explain_granted_group.add_argument(
        '--role',
        default=None,
        help='Query for a role')
    explain_granted_group.add_argument(
        '--permission',
        default=None,
        help='Query for a permission')

    explain_denied_parser = action_subparser.add_parser(
        'why_denied',
        help='Explain why a set of roles or permissions '
             'is denied for a member on a resource')
    explain_denied_parser.add_argument(
        'member',
        help='Member to query')
    explain_denied_parser.add_argument(
        'resources',
        nargs='+',
        help='Resource to query')
    explain_denied_group = (
        explain_denied_parser.add_mutually_exclusive_group(required=True))
    explain_denied_group.add_argument(
        '--roles',
        nargs='*',
        default=[],
        help='Query for roles')
    explain_denied_group.add_argument(
        '--permissions',
        nargs='*',
        default=[],
        help='Query for permissions')

    query_access_by_member = action_subparser.add_parser(
        'access_by_member',
        help='List access by member and permissions')
    query_access_by_member.add_argument(
        'member',
        help='Member to query')
    query_access_by_member.add_argument(
        'permissions',
        default=[],
        nargs='*',
        help='Permissions to query for')
    query_access_by_member.add_argument(
        '--expand_resources',
        action='store_true',
        help='Expand the resource hierarchy')

    query_access_by_authz = action_subparser.add_parser(
        'access_by_authz',
        help='List access by role or permission')
    query_access_by_authz.add_argument(
        '--permission',
        default=None,
        nargs='?',
        help='Permission to query')
    query_access_by_authz.add_argument(
        '--role',
        default=None,
        nargs='?',
        help='Role to query')
    query_access_by_authz.add_argument(
        '--expand_groups',
        action='store_true',
        help='Expand groups to their members')
    query_access_by_authz.add_argument(
        '--expand_resources',
        action='store_true',
        help='Expand resources to their children')

    query_access_by_resource = action_subparser.add_parser(
        'access_by_resource',
        help='List access by member and permissions')
    query_access_by_resource.add_argument(
        'resource',
        help='Resource to query')
    query_access_by_resource.add_argument(
        'permissions',
        default=[],
        nargs='*',
        help='Permissions to query for')
    query_access_by_resource.add_argument(
        '--expand_groups',
        action='store_true',
        help='Expand groups to their members')


def read_env(var_key, default):
    """Read an environment variable with a default value.

    Args:
        var_key (str): Environment key get.
        default (str): Default value if variable is not set.

    Returns:
        string: return environment value or default
    """

    var_value = os.environ[var_key] if var_key in os.environ else default

    LOGGER.info('reading environment variable %s = %s',
                var_key, var_value)

    return var_value


def define_parent_parser(parser_cls, config_env):
    """Define the parent parser.

    Args:
        parser_cls (type): Class to instantiate parser from.
        config_env (object): Configuration environment.

    Returns:
        argparser: The parent parser which has been defined.
    """

    LOGGER.debug('parser_cls = %s, config_env = %s',
                 parser_cls, config_env)

    parent_parser = parser_cls(prog='forseti')
    parent_parser.add_argument(
        '--endpoint',
        default=config_env['endpoint'],
        help='Server endpoint')
    parent_parser.add_argument(
        '--use_model',
        default=config_env['model'],
        help='Model to operate on')
    parent_parser.add_argument(
        '--out-format',
        default=config_env['format'],
        choices=['json'])
    return parent_parser


def create_parser(parser_cls, config_env):
    """Create argument parser hierarchy.

    Args:
        parser_cls (cls): Class to instantiate parser from.
        config_env (object): Configuration environment

    Returns:
        argparser: The argument parser hierarchy which is created.
    """

    main_parser = define_parent_parser(parser_cls, config_env)
    service_subparsers = main_parser.add_subparsers(
        title='service',
        dest='service')
    define_explainer_parser(service_subparsers)
    define_inventory_parser(service_subparsers)
    define_config_parser(service_subparsers)
    define_model_parser(service_subparsers)
    define_scanner_parser(service_subparsers)
    define_notifier_parser(service_subparsers)
    define_server_parser(service_subparsers)
    return main_parser


class Output(object):
    """Output base interface."""

    def write(self, obj):
        """Writes an object to the output channel.
            Args:
                obj (object): Object to write
            Raises:
                NotImplementedError: Always
        """
        raise NotImplementedError()


class JsonOutput(Output):
    """Raw output for result objects."""

    def write(self, obj):
        """Writes json representation.
            Args:
                obj (object): Object to write as json
        """
        print MessageToJson(obj, including_default_value_fields=True)


def run_config(_, config, output, config_env):
    """Run config commands.
        Args:
            _ (iam_client.ClientComposition): Unused.
            config (object): argparser namespace to use.
            output (Output): output writer to use.
            config_env (object): Configuration environment.
    """
    del output  # unused argument.

    def do_show_config():
        """Show the current config."""
        print config_env

    def do_set_endpoint():
        """Set a config item."""
        config_env['endpoint'] = config.hostport
        DefaultConfigParser.persist(config_env)
        do_show_config()

    def do_set_model():
        """Set a config item."""
        config_env['model'] = config.name
        DefaultConfigParser.persist(config_env)
        do_show_config()

    def do_set_output():
        """Set a config item."""
        config_env['format'] = config.name
        DefaultConfigParser.persist(config_env)
        do_show_config()

    def do_delete_config():
        """Delete a config item."""
        del config_env[config.key]
        DefaultConfigParser.persist(config_env)
        do_show_config()

    def do_reset_config():
        """Reset the config to default values."""
        for key in config_env:
            del config_env[key]
        DefaultConfigParser.persist(config_env)
        do_show_config()

    actions = {
        'show': do_show_config,
        'model': do_set_model,
        'endpoint': do_set_endpoint,
        'format': do_set_output,
        'reset': do_reset_config,
        'delete': do_delete_config}

    actions[config.action]()


def run_scanner(client, config, output, _):
    """Run scanner commands.
        Args:
            client (iam_client.ClientComposition): client to use for requests.
            config (object): argparser namespace to use.
            output (Output): output writer to use.
            _ (object): Configuration environment.
    """

    client = client.scanner
    scanner_name = config.scanner

    def do_run():
        """Run a scanner."""
        for progress in client.run(scanner_name):
            output.write(progress)

    actions = {
        'run': do_run}

    actions[config.action]()


def run_server(client, config, output, _):
    """Run scanner commands.
        Args:
            client (iam_client.ClientComposition): client to use for requests.
            config (object): argparser namespace to use.
            output (Output): output writer to use.
            _ (object): Configuration environment.
    """

    client = client.server_config

    def do_get_log_level():
        """Get the log level of the server."""
        output.write(client.get_log_level())

    def do_set_log_level():
        """Set the log level of the server."""
        output.write(client.set_log_level(config.log_level))

    def do_reload_configuration():
        """Reload the configuration of the server."""
        output.write(client.reload_server_configuration(
            config.config_file_path))

    def do_get_configuration():
        """Get the configuration of the server."""
        output.write(client.get_server_configuration())

    actions = {
        'log_level': {
            'get': do_get_log_level,
            'set': do_set_log_level
        },
        'configuration': {
            'get': do_get_configuration,
            'reload': do_reload_configuration
        }
    }

    actions[config.action][config.subaction]()


def run_notifier(client, config, output, _):
    """Run notifier commands.
        Args:
            client (iam_client.ClientComposition): client to use for requests.
            config (object): argparser namespace to use.
            output (Output): output writer to use.
            _ (object): Configuration environment.
    """

    client = client.notifier

    def do_run():
        """Run the notifier."""
        for progress in client.run(
                int(config.inventory_index_id),
                int(config.scanner_index_id)):
            output.write(progress)

    actions = {
        'run': do_run}

    actions[config.action]()


def run_model(client, config, output, config_env):
    """Run model commands.
        Args:
            client (iam_client.ClientComposition): client to use for requests.
            config (object): argparser namespace to use.
            output (Output): output writer to use.
            config_env (object): Configuration environment.
    """

    client = client.model

    def do_list_models():
        """List models."""
        for model in client.list_models():
            output.write(model)

    def do_get_model():
        """Get details of a model."""
        result = client.get_model(config.model)
        output.write(result)

    def do_delete_model():
        """Delete a model."""
        model = client.get_model(config.model)
        result = client.delete_model(model.handle)
        output.write(result)

    def do_create_model():
        """Create a model."""
        result = client.new_model('inventory',
                                  config.name,
                                  int(config.inventory_index_id),
                                  config.background)
        output.write(result)

    def do_use_model():
        """Use a model.

        Raises:
            Warning: When the specified model is not usable or not existed
        """
        model = client.get_model(config.model)
        if model and model.status in ['SUCCESS', 'PARTIAL_SUCCESS']:
            config_env['model'] = model.handle
        else:
            raise Warning('use_model failed, the specified model is '
                          'either not existed or not usable.')
        DefaultConfigParser.persist(config_env)

    actions = {
        'create': do_create_model,
        'list': do_list_models,
        'get': do_get_model,
        'delete': do_delete_model,
        'use': do_use_model}

    actions[config.action]()


def run_inventory(client, config, output, _):
    """Run inventory commands.
        Args:
            client (iam_client.ClientComposition): client to use for requests.
            config (object): argparser namespace to use.
            output (Output): output writer to use.
            _ (object): Unused.
    """

    client = client.inventory

    def do_create_inventory():
        """Create an inventory."""
        for progress in client.create(config.background,
                                      config.import_as,
                                      config.enable_debug):
            output.write(progress)

    def do_list_inventory():
        """List an inventory."""
        for inventory in client.list():
            output.write(inventory)

    def do_get_inventory():
        """Get an inventory."""
        result = client.get(int(config.id))
        output.write(result)

    def do_delete_inventory():
        """Delete an inventory."""
        result = client.delete(int(config.id))
        output.write(result)

    def do_purge_inventory():
        """Purge all inventory data older than the retention days."""
        result = client.purge(config.retention_days)
        output.write(result)

    actions = {
        'create': do_create_inventory,
        'list': do_list_inventory,
        'get': do_get_inventory,
        'delete': do_delete_inventory,
        'purge': do_purge_inventory}

    actions[config.action]()


def run_explainer(client, config, output, _):
    """Run explain commands.
        Args:
            client (iam_client.ClientComposition): client to use for requests.
            config (object): argparser namespace to use.
            output (Output): output writer to use.
            _ (object): Unused.
    """

    client = client.explain

    def do_list_resources():
        """List resources by prefix"""
        result = client.list_resources(config.prefix)
        output.write(result)

    def do_list_members():
        """List resources by prefix"""
        result = client.list_members(config.prefix)
        output.write(result)

    def do_list_roles():
        """List roles by prefix"""
        result = client.list_roles(config.prefix)
        output.write(result)

    def do_list_permissions():
        """List permissions by roles or role prefixes.

        Raises:
            ValueError: if neither a role nor a role prefix is set
        """
        if not any([config.roles, config.role_prefixes]):
            raise ValueError('please specify either a role or a role prefix')
        result = client.query_permissions_by_roles(config.roles,
                                                   config.role_prefixes)
        output.write(result)

    def do_get_policy():
        """Get access"""
        result = client.get_iam_policy(config.resource)
        output.write(result)

    def do_check_policy():
        """Check access"""
        result = client.check_iam_policy(config.resource,
                                         config.permission,
                                         config.member)
        output.write(result)

    def do_why_granted():
        """Explain why a permission or role is granted."""
        result = client.explain_granted(config.member,
                                        config.resource,
                                        config.role,
                                        config.permission)
        output.write(result)

    def do_why_not_granted():
        """Explain why a permission or a role is NOT granted."""
        result = client.explain_denied(config.member,
                                       config.resources,
                                       config.roles,
                                       config.permissions)
        output.write(result)

    def do_query_access_by_member():
        """Query access by member and permissions"""
        result = client.query_access_by_members(config.member,
                                                config.permissions,
                                                config.expand_resources)
        output.write(result)

    def do_query_access_by_resource():
        """Query access by resource and permissions"""
        result = client.query_access_by_resources(config.resource,
                                                  config.permissions,
                                                  config.expand_groups)
        output.write(result)

    def do_query_access_by_authz():
        """Query access by role or permission

        Raises:
            ValueError: if neither a role nor a permission is set
        """
        if not any([config.role, config.permission]):
            raise ValueError('please specify either a role or a permission')
        for access in (
                client.query_access_by_permissions(config.role,
                                                   config.permission,
                                                   config.expand_groups,
                                                   config.expand_resources)):
            output.write(access)

    actions = {
        'list_resources': do_list_resources,
        'list_members': do_list_members,
        'list_roles': do_list_roles,
        'get_policy': do_get_policy,
        'check_policy': do_check_policy,
        'why_granted': do_why_granted,
        'why_denied': do_why_not_granted,
        'list_permissions': do_list_permissions,
        'access_by_member': do_query_access_by_member,
        'access_by_resource': do_query_access_by_resource,
        'access_by_authz': do_query_access_by_authz}

    actions[config.action]()


OUTPUTS = {
    'json': JsonOutput,
}

SERVICES = {
    'explainer': run_explainer,
    'inventory': run_inventory,
    'config': run_config,
    'model': run_model,
    'scanner': run_scanner,
    'notifier': run_notifier,
    'server': run_server
}


class DefaultConfigParser(object):
    """Handles creation and persistence of DefaultConfig"""

    @classmethod
    def persist(cls, config):
        """Save a configuration file.

        Args:
            config (obj): Configuration to store.
        """

        with file(get_config_path(), 'w+') as outfile:
            json.dump(config, outfile)

    @classmethod
    def load(cls):
        """Open configuration file and create an instance from it.

        Returns:
            object: DefaultConfig.
        """

        try:
            with file(get_config_path()) as infile:
                return DefaultConfig(json.load(infile))
        except IOError:
            LOGGER.warn('IOError - trying to open configuration'
                        ' file located at %s', get_config_path())
            return DefaultConfig()


class DefaultConfig(dict):
    """Represents the configuration."""

    DEFAULT_ENDPOINT = 'localhost:50051'

    DEFAULT = {
        'endpoint': '',
        'model': '',
        'format': 'json',
    }

    def __init__(self, *args, **kwargs):
        """Constructor.

        Args:
            *args (list): Forwarded to base class.
            **kwargs (dict): Forwarded to base class.
        """
        super(DefaultConfig, self).__init__(*args, **kwargs)

        self.DEFAULT['endpoint'] = self.get_default_endpoint()

        # Initialize default values
        for key, value in self.DEFAULT.iteritems():
            if key not in self:
                self[key] = value

    def get_default_endpoint(self):
        """Get server address.

        Returns:
            str: Forseti server endpoint
        """
        default_env_variable = 'FORSETI_CLIENT_CONFIG'
        try:
            conf_path = os.environ[default_env_variable]
            configs = file_loader.read_and_parse_file(conf_path)
            server_ip = configs.get('server_ip')
            if server_ip:
                return '{}:50051'.format(server_ip)
        except KeyError:
            LOGGER.info('Unable to read environment variable: %s, will use '
                        'the default endpoint instead, endpoint: %s',
                        default_env_variable,
                        self.DEFAULT_ENDPOINT)
        except IOError:
            LOGGER.info('Unable to open file: %s, will use the default '
                        'endpoint instead, endpoint: %s',
                        conf_path,
                        self.DEFAULT_ENDPOINT)

        return self.DEFAULT_ENDPOINT

    def __getitem__(self, key):
        """Get item by key.

        Args:
            key (object): Key to get value for.

        Returns:
            object: Returns base classe setitem result.

        Raises:
            KeyError: If configuration key is unknown.
        """

        if key not in self.DEFAULT:
            error_message = 'Configuration key unknown: {}'.format(key)
            LOGGER.error(error_message)
            raise KeyError(error_message)
        return dict.__getitem__(self, key)

    def __setitem__(self, key, value):
        """Set item by key.

        Args:
            key (object): Key to set value for.
            value (object): Value to set.

        Returns:
            object: Returns base classe setitem result.

        Raises:
            KeyError: If configuration key is unknown.
        """

        if key not in self.DEFAULT:
            error_message = 'Configuration key unknown: {}'.format(key)
            LOGGER.error(error_message)
            raise KeyError(error_message)
        return dict.__setitem__(self, key, value)

    def __delitem__(self, key):
        """Delete item by key.

        Args:
            key (object): Key to delete value for

        Raises:
            KeyError: If configuration key is unknown.
        """

        if key not in self.DEFAULT:
            error_message = 'Configuration key unknown: {}'.format(key)
            LOGGER.error(error_message)
            raise KeyError(error_message)
        self[key] = self.DEFAULT[key]


def main(args=None,
         config_env=None,
         client=None,
         outputs=None,
         parser_cls=DefaultParser,
         services=None):
    """Main function.
    Args:
        args (list): CLI arguments.
        config_env (obj): Configuration environment.
        client (obj): API client to use.
        outputs (list): Supported output formats.
        parser_cls (type): Argument parser type to instantiate.
        services (list): Supported Forseti Server services.

    Returns:
        object: Environment configuration.
    """
    config_env = config_env or DefaultConfigParser.load()
    parser = create_parser(parser_cls, config_env)
    config = parser.parse_args(args)

    if not client:
        client = iam_client.ClientComposition(config.endpoint)
    client.switch_model(config.use_model)

    if not outputs:
        outputs = OUTPUTS
    if not services:
        services = SERVICES
    output = outputs[config.out_format]()
    try:
        services[config.service](client, config, output, config_env)
    except ValueError as e:
        parser.error(e.message)
    except grpc.RpcError as e:
        grpc_status_code = e.code()  # pylint: disable=no-member
        if grpc_status_code == grpc.StatusCode.UNAVAILABLE:
            print('Error communicating to the Forseti server.\n'
                  'Please check the status of the server and make sure it\'s '
                  'running.\n'
                  'If you are accessing from a client VM, make sure the '
                  '`server_ip` field inside the client configuration file in '
                  'the Forseti client GCS bucket contains the right IP '
                  'address.\n')
        else:
            print 'Error occurred on the server side, message: {}'.format(e)
    except ModelNotSetError:
        print ('Model must be specified before running this command. '
               'You can specify a model to use with command '
               '"forseti model use <MODEL_NAME>".')
    return config


def get_config_path():
    """Get configuration file path.

    Returns:
        str: Configuration path.
    """

    config_path = os.path.join(os.getenv('HOME'), '.forseti')
    return config_path


if __name__ == '__main__':
    main()
