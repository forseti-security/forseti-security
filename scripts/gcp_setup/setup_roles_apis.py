# Copyright 2017 The Forseti Security Authors. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Enable APIs and setup roles.

This has been tested with python 2.7.
"""

from __future__ import print_function

import argparse
import subprocess
import sys

from environment import gcloud_env


def run(argv):
    """Enable APIs and assign roles.

    Args:
        argv (list): The commandline args.
    """
    parser = _create_arg_parser()
    args = parser.parse_args(argv)

    apis = gcloud_env.REQUIRED_APIS

    if args.project_id:
        project_id = args.project_id
    else:
        project_id = subprocess.check_output([
            'gcloud', 'config', 'get-value', 'project']).strip()

    if args.dry_run:
        print('\nDry run only')
    else:
        print('\nEnable APIs and assign roles')

    print('\nEnabling required APIs:\n')
    for api in apis:
        cmd = ['gcloud', 'services', 'enable', api['service'], '--async']

        print('EXECUTE: %s' % ' '.join(cmd))
        if not args.dry_run:
            subprocess.call(cmd)

    _assign_roles(args, project_id)


def _create_arg_parser():
    """Get parser args.

    Returns:
        ArgumentParser: The args parsed.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument('--dry-run',
                        required=False,
                        action='store_true',
                        help='Dry run, just print the gcloud commands')
    roles_group = parser.add_argument_group('role target')
    roles_group_ex = roles_group.add_mutually_exclusive_group(required=True)
    roles_group_ex.add_argument('--org-id',
                                type=int,
                                help='Organization ID (number): '
                                     'Assign roles on Organization IAM policy. '
                                     'You need to be an Organization Admin.')
    roles_group_ex.add_argument('--folder-id',
                                type=int,
                                help='Folder ID (number): '
                                     'Assign roles on a Folder IAM policy.')
    roles_group_ex.add_argument('--project-id',
                                type=str,
                                help='Project ID (string): '
                                     'Assign roles on a Project IAM policy.')

    member_group = parser.add_argument_group('policy member')
    member_group_ex = member_group.add_mutually_exclusive_group(required=True)
    member_group_ex.add_argument('--user',
                                 type=str,
                                 help='Role member type=user')
    member_group_ex.add_argument('--group',
                                 type=str,
                                 help='Role member type=group')
    member_group_ex.add_argument('--service-account',
                                 type=str,
                                 help='Role member type=serviceAccount')
    return parser


def _get_resource_info(args):
    """Get the target resource information.

    Args:
        args (object): The args.

    Returns:
        list: The list of args to use with gcloud.
        str: The resource id.
    """
    resource_args = None
    resource_id = None

    if args.org_id:
        resource_args = ['organizations']
        resource_id = args.org_id
    elif args.folder_id:
        resource_args = ['alpha', 'resource-manager', 'folders']
        resource_id = args.folder_id
    elif args.project_id:
        resource_args = ['projects']
        resource_id = args.project_id

    return resource_args, resource_id


def _get_member(args):
    """Get member name and type.

    Args:
        args (object): The args.

    Returns:
        str: The member type.
        str: The member name.
    """
    member_type = None
    member_name = None

    if args.user:
        member_type = 'user'
        member_name = args.user
    elif args.group:
        member_type = 'group'
        member_name = args.group
    elif args.service_account:
        member_type = 'serviceAccount'
        member_name = args.service_account

    return member_type, member_name

def _assign_roles(args, project_id):
    """Assign roles.

    Args:
        args (object): The args.
        project_id (str): The project id.
    """
    api_roles = []
    api_roles.extend(gcloud_env.GCP_READ_IAM_ROLES)
    api_roles.extend(gcloud_env.GCP_WRITE_IAM_ROLES)
    util_roles = gcloud_env.PROJECT_IAM_ROLES

    print('\n\nAssigning roles:\n')
    resource_args, resource_id = _get_resource_info(args)
    if not resource_id:
        print('No org, folder, or project id. Exiting.')
        sys.exit(1)

    member_type, member_name = _get_member(args)
    if not member_type or not member_name:
        print('No member type or name.')
        sys.exit(1)

    for role in api_roles:
        cmd = ['gcloud']
        cmd.extend(resource_args)
        cmd.extend([
            'add-iam-policy-binding', str(resource_id),
            '--member=%s:%s' % (member_type, member_name), '--role=%s' % role])

        print('EXECUTE: %s' % ' '.join(cmd))
        if not args.dry_run:
            retcode, _, err = gcloud_env.run_command(cmd)
            if retcode:
                print(err)
            else:
                print('Done')

    for role in util_roles:
        cmd = [
            'gcloud', 'projects', 'add-iam-policy-binding', project_id,
            '--member=%s:%s' % (member_type, member_name),
            '--role=%s' % role]

        print('EXECUTE: %s' % ' '.join(cmd))
        if not args.dry_run:
            retcode, _, err = gcloud_env.run_command(cmd)
            if retcode:
                print(err)
            else:
                print('Done')


if __name__ == '__main__':
    run(sys.argv[1:])
