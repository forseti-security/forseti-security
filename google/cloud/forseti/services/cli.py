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

# pylint: disable=too-many-locals

from argparse import ArgumentParser
import json
import os
import sys
from google.protobuf.json_format import MessageToJson

from google.cloud.forseti.services import client as iam_client


def define_playground_parser(parent):
    """Define the playground service parser.

    Args:
        parent (argparser): Parent parser to hook into.
    """
    service_parser = parent.add_parser("playground", help="playground service")
    action_subparser = service_parser.add_subparsers(
        title="action",
        dest="action")

    add_role_parser = action_subparser.add_parser(
        'define_role',
        help='Defines a new role')
    add_role_parser.add_argument(
        'role',
        help='Role name to define')
    add_role_parser.add_argument(
        'permissions',
        nargs='+',
        help='Permissions contained in the role')

    del_role_parser = action_subparser.add_parser(
        'delete_role',
        help='Delete a role')
    del_role_parser.add_argument(
        'role',
        help='Role name to delete')

    list_roles_parser = action_subparser.add_parser(
        'list_roles',
        help='List roles by prefix')
    list_roles_parser.add_argument(
        '--prefix',
        default='',
        help='Role prefix to filter for')

    add_resource_parser = action_subparser.add_parser(
        'define_resource',
        help='Defines a new resource')
    add_resource_parser.add_argument(
        'resource_type_name',
        help='Resource type/name to define')
    add_resource_parser.add_argument(
        'parent_type_name',
        default=None,
        nargs='?',
        help='Parent type/name')
    add_resource_parser.add_argument(
        '--no-parent',
        default=False,
        type=bool,
        help='Set this flag if the resource is a root')

    del_resource_parser = action_subparser.add_parser(
        'delete_resource',
        help='Delete a resource')
    del_resource_parser.add_argument(
        'resource_type_name',
        help='Resource type/name to delete')

    list_resource_parser = action_subparser.add_parser(
        'list_resources',
        help='List resources by prefix')
    list_resource_parser.add_argument(
        '--prefix',
        default='',
        help='Resource prefix to filter for')

    add_member_parser = action_subparser.add_parser(
        'define_member',
        help='Defines a new member')
    add_member_parser.add_argument(
        'member',
        help='Member type/name to define')
    add_member_parser.add_argument(
        'parents',
        nargs='*',
        default=None,
        help='Parent type/names')

    del_member_parser = action_subparser.add_parser(
        'delete_member',
        help='Delete a member or relationship')
    del_member_parser.add_argument(
        'parent',
        help='Parent type/name in case of deleting a relationship')
    del_member_parser.add_argument(
        '--delete_relation_only',
        type=bool,
        default=False,
        help='Delete only the relationship, not the member itself')

    list_members_parser = action_subparser.add_parser(
        'list_members',
        help='List members by prefix')
    list_members_parser.add_argument(
        '--prefix',
        default='',
        help='Member prefix to filter for')

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

    set_policy = action_subparser.add_parser(
        'set_policy',
        help='Set a new policy on a resource')
    set_policy.add_argument(
        'resource',
        help='Resource to set policy on')
    set_policy.add_argument(
        'policy',
        help='Policy in json format')

    get_policy = action_subparser.add_parser(
        'get_policy',
        help='Get a resource\'s direct policy')
    get_policy.add_argument(
        'resource',
        help='Resource to get policy for')


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
        '--background',
        '-b',
        action='store_true',
        help='Execute inventory in background',
        )
    create_inventory_parser.add_argument(
        '--import_as',
        metavar=('MODEL_NAME',),
        help='Import the inventory when complete, requres a model name')

    delete_inventory_parser = action_subparser.add_parser(
        'delete',
        help='Delete an inventory')
    delete_inventory_parser.add_argument(
        'id',
        type=int,
        help='Inventory id to delete')

    _ = action_subparser.add_parser(
        'list',
        help='List all inventory')

    get_inventory_parser = action_subparser.add_parser(
        'get',
        help='Get a particular inventory')
    get_inventory_parser.add_argument(
        'id',
        type=int,
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
        choices=['json', 'text'],
        help='Configure the CLI output format')


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
        help='Model to switch to, either hash or name'
        )

    _ = action_subparser.add_parser(
        'list',
        help='List all available models')

    delete_model_parser = action_subparser.add_parser(
        'delete',
        help='Deletes an entire model')
    delete_model_parser.add_argument(
        'model',
        help='Model to delete')

    create_model_parser = action_subparser.add_parser(
        'create',
        help='Create a model')
    create_model_parser.add_argument(
        'source',
        choices=['empty', 'inventory'],
        help='Source to import from')
    create_model_parser.add_argument(
        'name',
        help='Human readable name for this model')
    create_model_parser.add_argument(
        '--id',
        type=int,
        default=-1,
        help='Inventory id to import from, if "inventory" source'
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

    create_scanner_parser = action_subparser.add_parser(
        'run',
        help='Run the scanner')

    create_scanner_parser.add_argument(
        'config_file',
        help='Scanner config file')


def define_explainer_parser(parent):
    """Define the explainer service parser.

    Args:
        parent (argparser): Parent parser to hook into.
    """
    service_parser = parent.add_parser('explainer', help='explain service')
    action_subparser = service_parser.add_subparsers(
        title='action',
        dest='action')

    _ = action_subparser.add_parser(
        'denormalize',
        help='Denormalize a model')

    explain_granted_parser = action_subparser.add_parser(
        'why_granted',
        help="""Explain why a role or permission
                is granted for a member on a resource""")
    explain_granted_parser.add_argument(
        'member',
        help='Member to query')
    explain_granted_parser.add_argument(
        'resource',
        help='Resource to query')
    explain_granted_parser.add_argument(
        '--role',
        default=None,
        help='Query for a role')
    explain_granted_parser.add_argument(
        '--permission',
        default=None,
        help='Query for a permission')

    explain_denied_parser = action_subparser.add_parser(
        'why_denied',
        help="""Explain why a set of roles or permissions
                is denied for a member on a resource""")
    explain_denied_parser.add_argument(
        'member',
        help='Member to query')
    explain_denied_parser.add_argument(
        'resources',
        nargs='+',
        help='Resource to query')
    explain_denied_parser.add_argument(
        '--roles',
        nargs='*',
        default=[],
        help='Query for roles')
    explain_denied_parser.add_argument(
        '--permissions',
        nargs='*',
        default=[],
        help='Query for permissions')

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
        type=bool,
        default=False,
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
        type=bool,
        default=False,
        help='Expand groups to their members')
    query_access_by_authz.add_argument(
        '--expand_resources',
        type=bool,
        default=False,
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
        type=bool,
        default=False,
        help='Expand groups to their members')


def define_iamql_parser(parent):
    """Define the IAMQL service parser.

    Args:
        parent (argparser): Parent parser to hook into.
    """
    service_parser = parent.add_parser('iamql', help='iamql service')
    action_subparser = service_parser.add_subparsers(
        title='action',
        dest='action')

    query_model_parser = action_subparser.add_parser(
        'query',
        help='Perform a query operation')
    query_model_parser.add_argument(
        'query_string',
        type=str,
        help='Query to perform')


def read_env(var_key, default):
    """Read an environment variable with a default value.

    Args:
        var_key (str): Environment key get.
        default (str): Default value if variable is not set.

    Returns:
        string: return environment value or default
    """
    return os.environ[var_key] if var_key in os.environ else default


def define_parent_parser(parser_cls, config_env):
    """Define the parent parser.
    Args:
        parser_cls (type): Class to instantiate parser from.
        config_env (object): Configuration environment.

    Returns:
        argparser: The parent parser which has been defined.
    """

    parent_parser = parser_cls()
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
        choices=['text', 'json'])
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
        title="service",
        dest="service")
    define_explainer_parser(service_subparsers)
    define_playground_parser(service_subparsers)
    define_inventory_parser(service_subparsers)
    define_config_parser(service_subparsers)
    define_model_parser(service_subparsers)
    define_scanner_parser(service_subparsers)
    define_iamql_parser(service_subparsers)

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


class TextOutput(Output):
    """Text output for result objects."""

    def write(self, obj):
        """Writes text representation.
            Args:
                obj (object): Object to write as string
        """
        print obj


class JsonOutput(Output):
    """Raw output for result objects."""

    def write(self, obj):
        """Writes json representation.
            Args:
                obj (object): Object to write as json
        """
        print MessageToJson(obj)


def run_config(_, config, output, config_env):
    """Run config commands.
        Args:
            _ (iam_client.ClientComposition): Unused.
            config (object): argparser namespace to use.
            output (Output): output writer to use.
            config_env (object): Configuration environment.
    """

    def do_show_config():
        """Show the current config."""
        if isinstance(output, TextOutput):
            output.write(config_env)
        else:
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

    def do_run():
        """Run a scanner."""
        result = client.run(config.config_file)
        output.write(result)

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
        result = client.list_models()
        output.write(result)

    def do_delete_model():
        """Delete a model."""
        result = client.delete_model(config.model)
        output.write(result)

    def do_create_model():
        """Create a model."""
        result = client.new_model(config.source,
                                  config.name,
                                  config.id,
                                  config.background)
        output.write(result)

    def do_use_model():
        """Use a model."""
        for model in client.list_models().models:
            if config.model == model.name or config.model == model.handle:
                config_env['model'] = model.handle
            DefaultConfigParser.persist(config_env)

    actions = {
        'create': do_create_model,
        'list': do_list_models,
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
                                      config.import_as):
            output.write(progress)

    def do_list_inventory():
        """List an inventory."""
        for inventory in client.list():
            output.write(inventory)

    def do_get_inventory():
        """Get an inventory."""
        result = client.get(config.id)
        output.write(result)

    def do_delete_inventory():
        """Delete an inventory."""
        result = client.delete(config.id)
        output.write(result)

    actions = {
        'create': do_create_inventory,
        'list': do_list_inventory,
        'get': do_get_inventory,
        'delete': do_delete_inventory}

    actions[config.action]()


def run_iamql(client, config, output, _):
    """Run IAMQL commands.
        Args:
            client (iam_client.ClientComposition): client to use for requests.
            config (object): argparser namespace to use.
            output (Output): output writer to use.
    """

    client = client.iamql

    def do_query():
        """Perform query operations."""

        for row in client.query(config.query_string):
            d = dict()
            for column in row.columns:
                if column.type == 0:
                    value = column.s
                elif column.type == 1:
                    value = column.b
                else:
                    value = column.n
                d[column.name] = value
            print json.dumps(d)

    actions = {
        'query': do_query}

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

    def do_denormalize():
        """Denormalize a model."""
        for access in client.denormalize():
            output.write(access)

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

    def do_list_permissions():
        """List permissions by roles or role prefixes."""
        result = client.query_permissions_by_roles(config.roles,
                                                   config.role_prefixes)
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
        """Query access by role or permission"""
        for access in (
                client.query_access_by_permissions(config.role,
                                                   config.permission,
                                                   config.expand_groups,
                                                   config.expand_resources)):

            output.write(access)

    actions = {
        'denormalize': do_denormalize,
        'why_granted': do_why_granted,
        'why_denied': do_why_not_granted,
        'list_permissions': do_list_permissions,
        'access_by_member': do_query_access_by_member,
        'access_by_resource': do_query_access_by_resource,
        'access_by_authz': do_query_access_by_authz}

    actions[config.action]()


def run_playground(client, config, output, _):
    """Run playground commands.
        Args:
            client (iam_client.ClientComposition): client to use for requests.
            config (object): argparser namespace to use.
            output (Output): output writer to use.
            _ (object): Unused.
    """

    client = client.playground

    def do_define_role():
        """Define a new role"""
        result = client.add_role(config.role,
                                 config.permissions)
        output.write(result)

    def do_delete_role():
        """Delete a role"""
        result = client.del_role(config.role)
        output.write(result)

    def do_list_roles():
        """List roles by prefix"""
        result = client.list_roles(config.prefix)
        output.write(result)

    def do_define_resource():
        """Define a new resource"""
        result = client.add_resource(config.resource_type_name,
                                     config.parent_type_name,
                                     config.no_parent)
        output.write(result)

    def do_delete_resource():
        """Delete a resource"""
        result = client.del_resource(config.resource_type_name)
        output.write(result)

    def do_list_resources():
        """List resources by prefix"""
        result = client.list_resources(config.prefix)
        output.write(result)

    def do_define_member():
        """Define a new member"""
        result = client.add_member(config.member,
                                   config.parents)
        output.write(result)

    def do_delete_member():
        """Delete a resource"""
        result = client.del_member(config.member,
                                   config.parent,
                                   config.delete_relation_only)
        output.write(result)

    def do_list_members():
        """List resources by prefix"""
        result = client.list_members(config.prefix)
        output.write(result)

    def do_check_policy():
        """Check access"""
        result = client.check_iam_policy(config.resource,
                                         config.permission,
                                         config.member)
        output.write(result)

    def do_get_policy():
        """Get access"""
        result = client.get_iam_policy(config.resource)
        output.write(result)

    def do_set_policy():
        """Set access"""
        result = client.set_iam_policy(config.resource,
                                       json.loads(config.policy))
        output.write(result)

    actions = {
        'define_role': do_define_role,
        'delete_role': do_delete_role,
        'list_roles': do_list_roles,
        'define_resource': do_define_resource,
        'delete_resource': do_delete_resource,
        'list_resources': do_list_resources,
        'define_member': do_define_member,
        'delete_member': do_delete_member,
        'list_members': do_list_members,
        'check_policy': do_check_policy,
        'get_policy': do_get_policy,
        'set_policy': do_set_policy}

    actions[config.action]()


OUTPUTS = {
    'text': TextOutput,
    'json': JsonOutput,
    }

SERVICES = {
    'explainer': run_explainer,
    'playground': run_playground,
    'inventory': run_inventory,
    'config': run_config,
    'model': run_model,
    'scanner': run_scanner,
    'iamql': run_iamql,
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
            return DefaultConfig()


class DefaultConfig(dict):
    """Represents the configuration."""

    DEFAULT = {
        'endpoint': 'localhost:50051',
        'model': '',
        'format': 'text',
        }

    def __init__(self, *args, **kwargs):
        """Constructor.

        Args:
            *args (list): Forwarded to base class.
            **kwargs (dict): Forwarded to base class.
        """
        super(DefaultConfig, self).__init__(*args, **kwargs)

        # Initialize default values
        for key, value in self.DEFAULT.iteritems():
            if key not in self:
                self[key] = value

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
            raise KeyError('Configuration key unknown: {}'.format(key))
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
            raise KeyError('Configuration key unknown: {}'.format(key))
        return dict.__setitem__(self, key, value)

    def __delitem__(self, key):
        """Delete item by key.

        Args:
            key (object): Key to delete value for

        Raises:
            KeyError: If configuration key is unknown.
        """

        if key not in self.DEFAULT:
            raise KeyError('Configuration key unknown: {}'.format(key))
        self[key] = self.DEFAULT[key]


def main(args,
         config_env,
         client=None,
         outputs=None,
         parser_cls=ArgumentParser,
         services=None):
    """Main function.
    Args:
        args (list): Command line arguments without argv[0].
        config_env (obj): Configuration environment.
        client (obj): API client to use.
        outputs (list): Supported output formats.
        parser_cls (type): Argument parser type to instantiate.
        services (list): Supported Forseti Server services.

    Returns:
        object: Environment configuration.
    """

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
    services[config.service](client, config, output, config_env)
    return config


def get_config_path():
    """Get configuration file path.

    Returns:
        str: Configuration path.
    """

    default_path = os.path.join(os.getenv('HOME'), '.forseti')
    config_path = read_env('FORSETI_CLIENT_CONFIG', default_path)
    return config_path


if __name__ == '__main__':
    ENV_CONFIG = DefaultConfigParser.load()
    main(sys.argv[1:], ENV_CONFIG)
