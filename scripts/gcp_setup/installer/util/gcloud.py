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

"""gcloud utility functions"""

from __future__ import print_function
import re
import sys
import json

from utils import run_command, print_banner, id_from_name
from constants import (
    GCLOUD_VERSION_REGEX, GCLOUD_ALPHA_REGEX, GCLOUD_MIN_VERSION,
    MESSAGE_GCLOUD_VERSION_MISMATCH, REQUIRED_APIS, GCP_READ_IAM_ROLES,
    GCP_WRITE_IAM_ROLES, PROJECT_IAM_ROLES_SERVER, SVC_ACCT_ROLES,
    MESSAGE_CREATE_ROLE_SCRIPT, QUESTION_CHOOSE_FOLDER,
    MESSAGE_BILLING_NOT_ENABLED, MESSAGE_NO_ORGANIZATION,
    RESOURCE_TYPE_ARGS_MAP, MESSAGE_NO_CLOUD_SHELL, PROJECT_IAM_ROLES_CLIENT)


def get_gcloud_info():
    """Read gcloud info, and check if running in Cloud Shell.

    Returns:
        str: GCP project id
        str: GCP Authenticated user
        bool: Whether or not the installer is running in cloudshell
    """
    return_code, out, err = run_command(
        ['gcloud', 'info', '--format=json'])
    if return_code:
        print(err)
        sys.exit(1)
    else:
        try:
            gcloud_info = json.loads(out)
            config = gcloud_info.get('config', {})
            project_id = config.get('project')
            authed_user = config.get('account')
            props = config.get('properties', {})
            metrics = props.get('metrics', {})
            is_devshell = metrics.get('environment') == 'devshell'
            print('Read gcloud info successfully')
        except ValueError as verr:
            print(verr)
            sys.exit(1)
    return project_id, authed_user, is_devshell


def verify_gcloud_information(project_id,
                              authed_user,
                              force_no_cloudshell,
                              is_devshell):
    """Verify all the gcloud related information are valid

    Args:
        project_id (str): project id
        authed_user (str): authenticated user
        force_no_cloudshell (bool): force no cloudshell
        is_devshell (bool): is dev shell
    """

    check_proper_gcloud()
    if not force_no_cloudshell:
        if not is_devshell:
            print(MESSAGE_NO_CLOUD_SHELL)
            sys.exit(1)
        else:
            print('Using Cloud Shell, continuing...')
    else:
        print('Bypass Cloud Shell check, continuing...')
    if not authed_user:
        print('Error getting authed user. You may need to run '
              '"gcloud auth login". Exiting.')
        sys.exit(1)
    print('You are: {}'.format(authed_user))

    if not project_id:
        print('You need to have an active project! Exiting.')
        sys.exit(1)
    print('Project id: %s' % project_id)


def check_proper_gcloud():
    """Check gcloud version and presence of alpha components."""
    return_code, out, err = run_command(
        ['gcloud', '--version'])

    version_regex = re.compile(GCLOUD_VERSION_REGEX)
    alpha_regex = re.compile(GCLOUD_ALPHA_REGEX)

    version = None
    alpha_match = None

    if return_code:
        print('Error trying to determine your gcloud version:')
        print(err)
        sys.exit(1)
    else:
        for line in out.split('\n'):
            version_match = version_regex.match(line)
            if version_match:
                version = tuple(
                    [int(i) for i in version_match.group(1).split('.')])
                continue
            alpha_match = alpha_regex.match(line)
            if alpha_match:
                break

    print('Current gcloud version: {}'.format('.'.join(
        [str(d) for d in version])))
    print('Gcloud alpha components? {}'.format(alpha_match is not None))
    if version < GCLOUD_MIN_VERSION or not alpha_match:
        print(MESSAGE_GCLOUD_VERSION_MISMATCH
              .format('.'.join([str(i) for i in GCLOUD_MIN_VERSION])))
        sys.exit(1)


def enable_apis(dry_run=False):
    """Enable necessary APIs for Forseti Security.

    Technically, this could be done in Deployment Manager, but if you
    delete the deployment, you'll disable the APIs. This could cause errors
    if there are resources still in use (e.g. Compute Engine), and then
    your deployment won't be cleanly deleted.

    Args:
        dry_run (bool): Whether this is a dry run. If True, don't actually
            enable the APIs.
    """
    print_banner('Enabling required APIs')
    if dry_run:
        # TODO: should we generate a script with the APIs to enable?
        print('This is a dry run, so skipping this step.')
        return

    for api in REQUIRED_APIS:
        print('Enabling the {} API...'.format(api['name']))
        return_code, _, err = run_command(
            ['gcloud', 'services', 'enable', api['service'], '--async'])
        if return_code:
            print(err)
        else:
            print('Done.')


def grant_client_svc_acct_roles(project_id,
                                gcp_service_account,
                                user_can_grant_roles):
    """Grant the following IAM roles to GCP service account.

    Project:
        Storage Object Viewer, Storage Object Creator, Logging LogWriter

    Args:
        project_id (str): GCP Project Id
        gcp_service_account (str): GCP service account email
        user_can_grant_roles (bool): Whether or not user has
                                        access to grant roles

    Returns:
        bool: Whether or not a role script has been generated
    """

    print_banner('Assigning roles to the GCP service account')

    roles = {
        'forseti_project': PROJECT_IAM_ROLES_CLIENT
    }

    return _grant_svc_acct_roles(
        False, None, project_id, None,
        gcp_service_account, user_can_grant_roles, roles)


def grant_server_svc_acct_roles(enable_write,
                                access_target,
                                target_id,
                                project_id,
                                gsuite_service_account,
                                gcp_service_account,
                                user_can_grant_roles):
    """Grant the following IAM roles to GCP service account.

    Org/Folder/Project:
        AppEngine App Viewer, Cloud SQL Viewer, Network Viewer
        Project Browser, Security Reviewer, Service Management Quota Viewer
        Security Admin

    Project:
        Cloud SQL Client, Storage Object Viewer, Storage Object Creator

    Args:
        enable_write (bool): Whether or not to enable write access
        access_target (str): Access target, either org, folder or project
        target_id (str): Id of the access_target
        project_id (str): GCP Project Id
        gsuite_service_account (str): GSuite service account email
        gcp_service_account (str): GCP service account email
        user_can_grant_roles (bool): Whether or not user has
                                        access to grant roles

    Returns:
        bool: Whether or not a role script has been generated
    """

    print_banner('Assigning roles to the GCP service account')
    access_target_roles = GCP_READ_IAM_ROLES
    if enable_write:
        access_target_roles.extend(GCP_WRITE_IAM_ROLES)

    roles = {
        '%ss' % access_target: access_target_roles,
        'forseti_project': PROJECT_IAM_ROLES_SERVER,
        'service_accounts': SVC_ACCT_ROLES,
    }

    return _grant_svc_acct_roles(
        enable_write ,target_id, project_id, gsuite_service_account,
        gcp_service_account, user_can_grant_roles, roles)


def _grant_svc_acct_roles(enable_write,
                          target_id,
                          project_id,
                          gsuite_service_account,
                          gcp_service_account,
                          user_can_grant_roles,
                          roles):
    """Grant roles to GCP service account.

    Args:
        enable_write (bool): Whether or not to enable write access
        target_id (str): Id of the access_target
        project_id (str): GCP Project Id
        gsuite_service_account (str): GSuite service account email
        gcp_service_account (str): GCP service account email
        user_can_grant_roles (bool): Whether or not user has
                                        access to grant roles
        roles (dict): Roles to grant
    Returns:
        bool: Whether or not a role script has been generated
    """

    access_target_roles = GCP_READ_IAM_ROLES
    if enable_write:
        access_target_roles.extend(GCP_WRITE_IAM_ROLES)

    assign_roles_cmds = _assign_roles(roles, target_id, project_id,
                                      gsuite_service_account,
                                      gcp_service_account,
                                      user_can_grant_roles)

    if assign_roles_cmds:
        print(MESSAGE_CREATE_ROLE_SCRIPT)

        with open('grant_forseti_roles.sh', 'wt') as roles_script:
            roles_script.write('#!/bin/bash\n\n')
            for cmd in assign_roles_cmds:
                roles_script.write('%s\n' % ' '.join(cmd))
        return True
    return False


def _assign_roles(roles_map, target_id, project_id,
                  gsuite_service_account, gcp_service_account,
                  user_can_grant_roles):
    """Assign the corresponding roles to users

    Args:
        roles_map (dict): A list of roles to assign
        target_id (str): Id of the access_target
        project_id (str): GCP Project Id
        gsuite_service_account (str): Gsuite service account email
        gcp_service_account (str): GCP service account email
        user_can_grant_roles (bool): Whether or not user has
                                     access to grant roles
    Returns:
        list: A list of roles that user couldn't grant
    """

    assign_roles_cmds = []

    for (resource_type, roles) in roles_map.iteritems():
        resource_args = RESOURCE_TYPE_ARGS_MAP[resource_type]
        if resource_type == 'forseti_project':
            resource_id = project_id
        elif resource_type == 'service_accounts':
            resource_id = gsuite_service_account
        else:
            resource_id = target_id

        for role in roles:
            iam_role_cmd = _grant_role(role, resource_args,
                                       resource_id, gcp_service_account,
                                       user_can_grant_roles)
            if iam_role_cmd is not None:
                assign_roles_cmds.append(iam_role_cmd)
    return assign_roles_cmds


def _grant_role(role, resource_args, resource_id,
                gcp_service_account, user_can_grant_roles):
    """ Grant role to the give service account

    Args:
        role (str): Role to grant
        resource_args (list): Resource arguments
        resource_id (str): Id of the resource
        gcp_service_account (str): GCP service account
        user_can_grant_roles (bool): Whether or not user has
                                     access to grant roles

    Returns:
        str: A command to grant the IAM role
    """
    iam_role_cmd = ['gcloud']
    iam_role_cmd.extend(resource_args)
    iam_role_cmd.extend([
        'add-iam-policy-binding',
        resource_id,
        '--member=serviceAccount:{}'.format(
            gcp_service_account),
        '--role={}'.format(role),
    ])
    if user_can_grant_roles:
        print('Assigning {} on {}...'.format(role, resource_id))
        return_code, _, err = run_command(iam_role_cmd)
        if return_code:
            print(err)
        else:
            print('Done.')
            return None

    return iam_role_cmd


def choose_organization():
    """Allow user to input organization id.

    Returns:
        str: Access target id
    """
    target_id = None
    while not target_id:
        orgs = None
        return_code, out, err = run_command([
            'gcloud', 'organizations', 'list', '--format=json'])
        if return_code:
            print(err)
        else:
            try:
                orgs = json.loads(out)
            except ValueError as verr:
                print(verr)

        if not orgs:
            print('\nYou don\'t have access to any organizations. '
                  'Choose another option to enable Forseti access.')
            return None

        print('\nHere are the organizations you have access to:')

        valid_org_ids = set()

        for org in orgs:
            org_id = id_from_name(org['name'])
            valid_org_ids.add(org_id)
            print('ID=%s (description="%s")' %
                  (org_id, org['displayName']))

        choice = raw_input('Enter the organization id where '
                           'you want Forseti to crawl for data: ').strip()
        try:
            # make sure that the choice is a valid organization id
            if choice not in valid_org_ids:
                print('Invalid organization id %s, try again' % choice)
                return None
            target_id = str(int(choice))
        except ValueError:
            print('Unable to parse organization id %s' % choice)
    return target_id


def choose_folder(organization_id):
    """Allow user to input folder id.

    Args:
        organization_id (str): GCP Organization Id

    Returns:
        str: Access target id
    """
    target_id = None
    while not target_id:
        choice = raw_input(
            QUESTION_CHOOSE_FOLDER.format(organization_id)).strip()
        try:
            # make sure that the choice is an int before converting to str
            target_id = str(int(choice))
        except ValueError:
            print('Invalid choice %s, try again' % choice)
    return target_id


def choose_project():
    """Allow user to input project id.

    Returns:
        str: Access target id
    """
    target_id = None
    while not target_id:
        target_id = raw_input(
            'Enter the project id (NOT PROJECT NUMBER), '
            'where you want Forseti to crawl for data: ').strip()
    return target_id


def create_reuse_service_acct(acct_type, acct_id, advanced_mode, dry_run):
    """Create or reuse service account.

    Args:
        acct_type (str): The account type
        acct_id (str): Account id
        advanced_mode (bool): Whether or not the installer is in advanced mode
        dry_run (bool): Whether or not the installer is in dry run mode

    Returns:
        str: The final account id that we will be using throughout
                the installation
    """
    print_banner('Create/Reuse {}'.format(acct_type))

    choices = ['Create {}'.format(acct_type), 'Reuse {}'.format(acct_type)]

    if not advanced_mode:
        choice_index = 1
    else:
        print_fun = lambda ind, val: print('[{}] {}'.format(ind + 1, val))
        choice_index = _get_choice_id(choices, print_fun)

    # If the choice is "Create service account", create the service
    # account. The default is to create the service account with a
    # generated name.
    # Otherwise, present the user with options to choose from
    # available service accounts in this project.
    if choice_index == 1 and dry_run:
        print('This is a dry run, so don\'t actually create '
              'the service account.')
    elif choice_index == 1:
        return_code, out, err = run_command(
            ['gcloud', 'iam', 'service-accounts', 'create',
             acct_id[:acct_id.index('@')], '--display-name', acct_type])
        if return_code:
            print(err)
            print('Could not create the service account. Terminating '
                  'because this is an unexpected error.')
            sys.exit(1)
    else:
        return_code, out, err = run_command(
            ['gcloud', 'iam', 'service-accounts', 'list', '--format=json'])
        if return_code:
            print(err)
            print('Could not determine the service accounts, will just '
                  'create a new service account.')
            return acct_id
        else:
            try:
                svc_accts = json.loads(out)
            except ValueError:
                print('Could not determine the service accounts, will just '
                      'create a new service account.')
                return acct_id

        print_fun = lambda ind, val: print('[{}] {} ({})'
                                           .format(ind+1,
                                                   val.get('displayName', ''),
                                                   val['email']))
        acct_idx = _get_choice_id(svc_accts, print_fun)
        acct_id = svc_accts[acct_idx - 1]['email']

    return acct_id


def _get_choice_id(choices, print_function):
    """Get choice id from user

    Args:
        choices (list): A list of choices
        print_function (function): Print function
    Returns:
        int: choice id
    """
    while True:
        for (i, choice) in enumerate(choices):
            print_function(i, choice)

        choice_input = raw_input(
            'Enter the number of your choice: ').strip()

        try:
            choice_index = int(choice_input)
            if choice_index < 1 or choice_index > len(choices):
                raise ValueError
            else:
                break
        except ValueError:
            print('Invalid choice "%s", try again' % choice_input)
    return choice_index


def check_billing_enabled(project_id, organization_id):
    """Check if billing is enabled.

    Args:
        project_id (str): GCP project id
        organization_id (str): GCP organization id
    """

    def _billing_not_enabled():
        """Print message and exit."""
        print(MESSAGE_BILLING_NOT_ENABLED.format(project_id, organization_id))
        sys.exit(1)
    return_code, out, err = run_command(
        ['gcloud', 'alpha', 'billing', 'projects', 'describe',
         project_id, '--format=json'])
    if return_code:
        print(err)
        _billing_not_enabled()
    try:
        billing_info = json.loads(out)
        if billing_info.get('billingEnabled'):
            print('Billing is enabled.')
        else:
            _billing_not_enabled()
    except ValueError:
        _billing_not_enabled()


def lookup_organization(project_id):
    """Infer the organization from the project's parent.

    Args:
        project_id (str): GCP project id

    Returns:
        str: GCP organization id
    """

    def _no_organization():
        """No organization, so print a message and exit."""
        print(MESSAGE_NO_ORGANIZATION)
        sys.exit(1)

    def _find_org_from_folder(folder_id):
        """Find the organization from some folder.

        Args:
            folder_id (str): The folder id, just a number.

        Returns:
            str: GCP organization id of the folder
        """
        cur_type = 'folders'
        cur_id = folder_id
        while cur_type != 'organizations':
            ret_code, output, error = run_command(
                ['gcloud', 'alpha', 'resource-manager', 'folders',
                 'describe', cur_id, '--format=json'])
            if ret_code:
                print(error)
                _no_organization()
            try:
                folder = json.loads(output)
                cur_type, cur_id = folder['parent'].split('/')
                print('Check parent: %s' % folder['parent'])
            except ValueError as verr:
                print(verr)
                _no_organization()
        return cur_id

    return_code, out, err = run_command(
        ['gcloud', 'projects', 'describe',
         project_id, '--format=json'])
    if return_code:
        print(err)
        print('Error trying to find current organization from '
              'project! Exiting.')
        sys.exit(1)

    try:
        project = json.loads(out)
        project_parent = project.get('parent')
        if not project_parent:
            _no_organization()
        parent_type = project_parent['type']
        parent_id = project_parent['id']
    except ValueError:
        print('Error retrieving organization id')
        _no_organization()

    if parent_type == 'folder':
        organization_id = _find_org_from_folder(parent_id)
    elif parent_type == 'organization':
        organization_id = parent_id
    else:
        _no_organization()
    if organization_id:
        print('Organization id: %s' % organization_id)
        return organization_id


def get_forseti_server_info():
    """ Get forseti server ip and zone information if exists, exit if not.

    Returns:
        str: IP address of the forseti server application
        str: Zone of the forseti server application, default to 'us-central1-c'
    """
    return_code, out, err = run_command(
        ['gcloud', 'compute', 'instances', 'list', '--format=json'])

    if return_code:
        print (err)
        sys.exit(1)
    try:
        instances = json.loads(out)
        for instance in instances:
            if 'forseti-security-server' in instance.get('name'):
                # found forseti server vm instance
                zone = instance.get('zone').split("/zones/")[1]
                network_interfaces = instance.get('networkInterfaces')
                internal_ip = network_interfaces[0].get('networkIP')
                return internal_ip, zone
    except ValueError:
        print('Error retrieving forseti server ip address, '
              'will leave the server ip empty for now.')
    return '', 'us-central1-c'
