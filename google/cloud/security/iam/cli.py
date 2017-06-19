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

""" IAM Explain CLI. """

#pylint: disable=too-many-locals

import argparse
import os
from google.protobuf.json_format import MessageToJson

from google.cloud.security.iam import client as iam_client


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
        'list_models',
        help='List all available models')

    delete_model_parser = action_subparser.add_parser(
        'delete_model',
        help='Deletes an entire model')
    delete_model_parser.add_argument(
        'model',
        help='Model to delete')

    create_model_parser = action_subparser.add_parser(
        'create_model',
        help='Create a model')
    create_model_parser.add_argument(
        'source',
        choices=['forseti', 'empty'],
        help='')

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


def read_env(var_key, default):
    """Read an environment variable with a default value.

    Args:
        var_key (str): Environment key get.
        default (str): Default value if variable is not set.

    Returns:
        string: return environment value or default
    """
    return os.environ[var_key] if var_key in os.environ else default


def define_parent_parser():
    """Define the parent parser.

    Returns:
        argparser: The parent parser which has been defined.
    """

    parent_parser = argparse.ArgumentParser()
    parent_parser.add_argument(
        '--endpoint',
        default='localhost:50051',
        help='Server endpoint')
    parent_parser.add_argument(
        '--use_model',
        default=read_env('IAM_MODEL', ''),
        help='Model to operate on')
    parent_parser.add_argument(
        '--out-format',
        default='text',
        choices=['text', 'json'])
    return parent_parser


def create_parser():
    """Create argument parser hierarchy.

    Returns:
        argparser: The argument parser hierarchy which is created.
    """
    main_parser = define_parent_parser()
    service_subparsers = main_parser.add_subparsers(
        title="service",
        dest="service")
    define_explainer_parser(service_subparsers)
    define_playground_parser(service_subparsers)
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


def run_explainer(client, config, output):
    """Run explain commands.
        Args:
            client (iam_client.ClientComposition): client to use for requests.
            config (object): argparser namespace to use.
            output (Output): output writer to use.
    """

    client = client.explain

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
        result = client.new_model(config.source)
        output.write(result)

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

    actions = {
        'list_models': do_list_models,
        'delete_model': do_delete_model,
        'create_model': do_create_model,
        'denormalize': do_denormalize,
        'why_granted': do_why_granted,
        'why_denied': do_why_not_granted,
        'list_permissions': do_list_permissions,
        'access_by_member': do_query_access_by_member,
        'access_by_resource': do_query_access_by_resource}

    actions[config.action]()


def run_playground(client, config, output):
    """Run playground commands.
        Args:
            client (iam_client.ClientComposition): client to use for requests.
            config (object): argparser namespace to use.
            output (Output): output writer to use.
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
                                       config.policy)
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
    }


def main():
    """Main function."""
    parser = create_parser()
    config = parser.parse_args()
    client = iam_client.ClientComposition(config.endpoint)
    client.switch_model(config.use_model)

    output = OUTPUTS[config.out_format]()
    SERVICES[config.service](client, config, output)


if __name__ == '__main__':
    main()
