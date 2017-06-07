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

import argparse
import os

from google.cloud.security.iam import client as iam_client


def define_playground_parser(parent):
    """Define the playground service parser."""
    service_parser = parent.add_parser("playground", help="playground service")
    action_subparser = service_parser.add_subparsers(
        title="action",
        dest="action")
    add_resource = action_subparser.add_parser(
        "add_resource",
        help="add a resource to the model")
    del_resource = action_subparser.add_parser(
        "del_resource",
        help="delete a resource from the model")


def define_explainer_parser(parent):
    """Define the explainer service parser."""
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
        help='Explain why a role or permission is granted for a member on a resource')
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
        help='Explain why a set of roles or permissions is denied for a member on a resource')
    explain_denied_parser.add_argument(
        'member',
        help='Member to query')
    explain_denied_parser.add_argument(
        'resource',
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

    query_permissions_by_roles_parser = action_subparser.add_parser(
        'list_permissions',
        help='List permissions by role(s)')
    query_permissions_by_roles_parser.add_argument(
        '--roles',
        default=[],
        help='Role names')
    query_permissions_by_roles_parser.add_argument(
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


def read_model_env():
    model_key = 'IAM_MODEL'
    return os.environ[model_key] if model_key in os.environ else ''

def define_parent_parser():
    """Define the parent parser."""
    parent_parser = argparse.ArgumentParser()
    parent_parser.add_argument(
        '--endpoint',
        default='localhost:50051',
        help='Server endpoint')
    parent_parser.add_argument(
        '--use_model',
        default=read_model_env(),
        help='Model to operate on')
    return parent_parser


def create_parser():
    """Create argument parser hierarchy."""
    main_parser = define_parent_parser()
    service_subparsers = main_parser.add_subparsers(
        title="service",
        dest="service")
    define_explainer_parser(service_subparsers)
    define_playground_parser(service_subparsers)
    return main_parser


def run_explainer(client, config):
    """Run explain commands."""

    def do_list_models():
        """List models."""
        print client.list_models()

    def do_delete_model():
        """Delete a model."""
        print client.delete_model(config.model)

    def do_create_model():
        """Create a model."""
        print client.new_model(config.source)

    def do_denormalize():
        """Denormalize a model."""
        for access in client.denormalize():
            print access

    def do_why_granted():
        """Explain why a permission or role is granted."""
        print client.explain_granted(config.member,
                                     config.resource,
                                     config.role,
                                     config.permission)

    def do_why_not_granted():
        """Explain why a permission or a role is NOT granted."""
        print client.explain_denied(config.member,
                                    config.resources,
                                    config.roles,
                                    config.permissions)

    def do_list_permissions():
        """List permissions by roles or role prefixes."""
        print client.query_permissions_by_roles(config.roles,
                                                config.role_prefixes)

    def do_query_access_by_member():
        """Query access by member and permissions"""
        print client.query_access_by_members(config.member,
                                             config.permissions,
                                             config.expand_resources)

    def do_query_access_by_resource():
        """Query access by resource and permissions"""
        print client.query_access_by_resources(config.resource,
                                               config.permissions,
                                               config.expand_groups)

    actions = {
            'list_models': do_list_models,
            'delete_model': do_delete_model,
            'create_model': do_create_model,
            'denormalize': do_denormalize,
            'why_granted': do_why_granted,
            'why_denied': do_why_not_granted,
            'list_permissions': do_list_permissions,
            'access_by_member': do_query_access_by_member,
            'access_by_resource': do_query_access_by_resource,
        }

    actions[config.action]()


def run_playground(client, config):
    """Run playground commands."""
    pass


def main():
    """Main function."""
    parser = create_parser()
    config = parser.parse_args()
    print config
    client = iam_client.ClientComposition(config.endpoint)
    client.switch_model(config.use_model)
    if config.service == 'explainer':
        run_explainer(client.explain, config)
    elif config.service == 'playground':
        run_playground(client.playground, config)
    else:
        raise NotImplementedError('Unknown service: {}'.format(config.service))


if __name__ == '__main__':
    main()
