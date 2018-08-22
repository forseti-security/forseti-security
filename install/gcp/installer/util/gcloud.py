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

"""Gcloud utility functions."""

from __future__ import print_function
import json
import re
import sys

import constants
import utils


def get_gcloud_info():
    """Read gcloud info, and check if running in Cloud Shell.

    Returns:
        str: GCP project id
        str: GCP Authenticated user
        bool: Whether or not the installer is running in cloudshell
    """
    return_code, out, err = utils.run_command(
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
            print('Read gcloud info: Success')
        except ValueError as verr:
            print(verr)
            sys.exit(1)
    return project_id, authed_user, is_devshell


def set_network_host_project_id(self):
    """Get the host project."""
    if not self.config.vpc_host_project_id:
        self.config.vpc_host_project_id, _, _ = get_gcloud_info()
    print('VPC Host Project %s' % self.config.vpc_host_project_id)


def activate_service_account(key_file):
    """Activate the service account with gcloud.

    Args:
        key_file (str): Absolute path to service account key file
    """

    return_code, _, err = utils.run_command(
        ['gcloud', 'auth', 'activate-service-account',
         '--key-file=' + key_file])

    if return_code:
        print(err)
        sys.exit(1)

    print('Service account activated')


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
    if not force_no_cloudshell and not is_devshell:
        print(constants.MESSAGE_NO_CLOUD_SHELL)
        sys.exit(1)

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
    return_code, out, err = utils.run_command(
        ['gcloud', '--version'])

    version_regex = re.compile(constants.GCLOUD_VERSION_REGEX)
    alpha_regex = re.compile(constants.GCLOUD_ALPHA_REGEX)

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
    print('Gcloud alpha components: {}'.format(alpha_match is not None))
    if version < constants.GCLOUD_MIN_VERSION or not alpha_match:
        print(constants.MESSAGE_GCLOUD_VERSION_MISMATCH
              .format('.'.join([str(i) for i in constants.GCLOUD_MIN_VERSION]))
             )
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
    utils.print_banner('Enabling Required APIs')
    if dry_run:
        print('This is a dry run, so skipping this step.')
        return

    for api in constants.REQUIRED_APIS:
        print('Enabling the {} API... '.format(api['name']),
              end='')
        sys.stdout.flush()
        return_code, _, err = utils.run_command(
            ['gcloud', 'services', 'enable', api['service']],
            number_of_retry=5,
            timeout_in_second=120)
        if return_code:
            print(err)
        else:
            print('enabled')


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

    utils.print_banner('Assigning Roles To The GCP Service Account',
                       gcp_service_account)

    roles = {
        'forseti_project': constants.PROJECT_IAM_ROLES_CLIENT
    }

    # Forseti client doesn't have target id and gsuite account.
    target_id = ''

    return _grant_svc_acct_roles(
        target_id, project_id, gcp_service_account,
        user_can_grant_roles, roles)


def grant_server_svc_acct_roles(enable_write,
                                access_target,
                                target_id,
                                project_id,
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
        gcp_service_account (str): GCP service account email
        user_can_grant_roles (bool): Whether or not user has
                                        access to grant roles

    Returns:
        bool: Whether or not a role script has been generated
    """

    utils.print_banner('Assigning Roles To The GCP Service Account',
                       gcp_service_account)
    access_target_roles = constants.GCP_READ_IAM_ROLES
    if enable_write:
        access_target_roles.extend(constants.GCP_WRITE_IAM_ROLES)

    roles = {
        '%ss' % access_target: access_target_roles,
        'forseti_project': constants.PROJECT_IAM_ROLES_SERVER,
        'service_accounts': constants.SVC_ACCT_ROLES,
    }

    return _grant_svc_acct_roles(
        target_id, project_id, gcp_service_account,
        user_can_grant_roles, roles)


def _grant_svc_acct_roles(target_id,
                          project_id,
                          gcp_service_account,
                          user_can_grant_roles,
                          roles):
    """Grant roles to GCP service account.

    Args:
        target_id (str): Id of the access_target
        project_id (str): GCP Project Id
        gcp_service_account (str): GCP service account email
        user_can_grant_roles (bool): Whether or not user has
                                        access to grant roles
        roles (dict): Roles to grant
    Returns:
        bool: Whether or not a role script has been generated
    """

    grant_roles_cmds = _grant_roles(roles, target_id, project_id,
                                    gcp_service_account,
                                    user_can_grant_roles)

    if grant_roles_cmds:
        print(constants.MESSAGE_CREATE_ROLE_SCRIPT)

        with open('grant_forseti_roles.sh', 'wt') as roles_script:
            roles_script.write('#!/bin/bash\n\n')
            for cmd in grant_roles_cmds:
                roles_script.write('%s\n' % ' '.join(cmd))
        return True
    return False


def _grant_roles(roles_map, target_id, project_id,
                 gcp_service_account,
                 user_can_grant_roles):
    """Assign the corresponding roles to users.

    Args:
        roles_map (dict): A list of roles to assign
        target_id (str): Id of the access_target
        project_id (str): GCP Project Id
        gcp_service_account (str): GCP service account email
        user_can_grant_roles (bool): Whether or not user has
                                     access to grant roles
    Returns:
        list: A list of roles that user couldn't grant
    """

    assign_roles_cmds = []

    for (resource_type, roles) in roles_map.iteritems():
        resource_args = constants.RESOURCE_TYPE_ARGS_MAP[resource_type]
        if resource_type == 'forseti_project':
            resource_id = project_id
        elif resource_type == 'service_accounts':
            # The role 'iam.serviceAccountTokenCreator' is needed by the
            # service account on itself therefore self assigning the role.
            resource_id = gcp_service_account
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
    """ Grant role to the give service account.

    Args:
        role (str): Role to grant
        resource_args (list): Resource arguments
        resource_id (str): Id of the resource
        gcp_service_account (str): GCP service account
        user_can_grant_roles (bool): Whether or not user has
                                     access to grant roles

    Returns:
        str: A command to grant the IAM role if the role was
            not granted successfully
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
        print('Assigning {} on {}... '.format(role, resource_id), end='')
        sys.stdout.flush()
        return_code, _, err = utils.run_command(iam_role_cmd)
        if return_code:
            print(err)
        else:
            print('assigned')
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
        return_code, out, err = utils.run_command([
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
            org_id = utils.id_from_name(org['name'])
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
            constants.QUESTION_CHOOSE_FOLDER.format(organization_id)).strip()
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


def create_or_reuse_service_acct(acct_type,
                                 acct_name,
                                 acct_email,
                                 advanced_mode,
                                 dry_run):
    """Create or reuse service account.

    Args:
        acct_type (str): The account type.
        acct_name (str): The account name.
        acct_email (str): Account id.
        advanced_mode (bool): Whether or not the installer is in advanced mode.
        dry_run (bool): Whether or not the installer is in dry run mode.

    Returns:
        str: The final account email that we will be using throughout
            the installation.
    """

    choices = ['Create {}'.format(acct_type), 'Reuse {}'.format(acct_type)]

    if not advanced_mode:
        print ('Creating {}... '.format(acct_type), end='')
        sys.stdout.flush()
        choice_index = 1
    else:
        print_fun = lambda ind, val: print('[{}] {}'.format(ind + 1, val))
        choice_index = utils.get_choice_id(choices, print_fun)

    # If the choice is "Create service account", create the service
    # account. The default is to create the service account with a
    # generated name.
    # Otherwise, present the user with options to choose from
    # available service accounts in this project.
    if choice_index == 1 and dry_run:
        print('This is a dry run, so don\'t actually create '
              'the service account.')
    elif choice_index == 1:
        return_code, out, err = utils.run_command(
            ['gcloud', 'iam', 'service-accounts', 'create',
             acct_email[:acct_email.index('@')], '--display-name',
             acct_name])
        if return_code:
            print(err)
            print('Could not create the service account. Terminating '
                  'because this is an unexpected error.')
            sys.exit(1)
        print ('created')
    else:
        return_code, out, err = utils.run_command(
            ['gcloud', 'iam', 'service-accounts', 'list', '--format=json'])
        if return_code:
            print(err)
            print('Could not determine the service accounts, will just '
                  'create a new service account.')
            return acct_email
        else:
            try:
                svc_accts = json.loads(out)
            except ValueError:
                print('Could not determine the service accounts, will just '
                      'create a new service account.')
                return acct_email

        print_fun = lambda ind, val: print('[{}] {} ({})'
                                           .format(ind+1,
                                                   val.get('displayName', ''),
                                                   val['email']))
        acct_idx = utils.get_choice_id(svc_accts, print_fun)
        acct_email = svc_accts[acct_idx - 1]['email']
    print ('\t{}'.format(acct_email))
    return acct_email


def check_billing_enabled(project_id, organization_id):
    """Check if billing is enabled.

    Args:
        project_id (str): GCP project id
        organization_id (str): GCP organization id
    """

    def _billing_not_enabled():
        """Print message and exit."""
        print(constants.MESSAGE_BILLING_NOT_ENABLED.format(
            project_id, organization_id))
        sys.exit(1)
    return_code, out, err = utils.run_command(
        ['gcloud', 'alpha', 'billing', 'projects', 'describe',
         project_id, '--format=json'])
    if return_code:
        print(err)
        _billing_not_enabled()
    try:
        billing_info = json.loads(out)
        if billing_info.get('billingEnabled'):
            print('Billing: Enabled')
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
        print(constants.MESSAGE_NO_ORGANIZATION)
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
            ret_code, output, error = utils.run_command(
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

    return_code, out, err = utils.run_command(
        ['gcloud', 'projects', 'describe',
         project_id, '--format=json'])
    if return_code:
        print(err)
        print('Error trying to find current organization from '
              'project! Exiting.')

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
        str: Name of the forseti server instance
    """
    ip_addr, zone, name = get_vm_instance_info('forseti-server',
                                               try_match=True)

    if ip_addr is None:
        print('No forseti server detected, you will need to install'
              ' forseti server before installing the client, exiting...')
        sys.exit(1)

    return ip_addr, zone, name


def get_vm_instance_info(instance_name, try_match=False):
    """Get forseti server ip and zone information if exists, exit if not.

    Args:
        instance_name (str): Name of the vm instance.
        try_match (bool): Match instance that contains instance_name.
                          inside their name.

    Returns:
        str: IP address of the forseti server application.
        str: Zone of the forseti server application, default to 'us-central1-c'.
        str: Name of the forseti server instance.
    """
    def _ping_compute_instance():
        """Check compute instance status."""
        utils.run_command(
            ['gcloud', 'compute', 'instances', 'list', '--format=json'])

    _ping_compute_instance()

    return_code, out, err = utils.run_command(
        ['gcloud', 'compute', 'instances', 'list', '--format=json'])

    if return_code:
        print (err)
        sys.exit(1)
    try:
        instances = json.loads(out)
        for instance in instances:
            cur_instance_name = instance.get('name')
            match = (try_match and re.match(instance_name, cur_instance_name) or
                     (not try_match and instance_name == cur_instance_name))
            if match:
                # found forseti server vm instance
                zone = instance.get('zone').split('/zones/')[1]
                network_interfaces = instance.get('networkInterfaces')
                internal_ip = network_interfaces[0].get('networkIP')
                name = instance.get('name')
                return internal_ip, zone, name
    except ValueError:
        print('Error retrieving forseti server ip address, '
              'will leave the server ip empty for now.')
    return None, None, None

def create_firewall_rule(rule_name,
                         service_accounts,
                         action,
                         rules,
                         direction,
                         priority,
                         vpc_host_network,
                         source_ranges=None):
    """Create a firewall rule for a specific gcp service account.

    Args:
        rule_name (str): Name of the firewall rule
        service_accounts (list): Target service account
        action (FirewallRuleAction): ALLOW or DENY
        rules (list): [PROTOCOL[:PORT[-PORT]],...]
                    will not be used if action is passed in
        direction (FirewallRuleDirection): INGRESS, EGRESS, IN or OUT
        priority (int): Integer between 0 and 65535
        vpc_host_network (str): vpc_host_network (str): Name of the VPC network
                              to create firewall rules in
        source_ranges (str): A list of IP address blocks that are allowed
                            to make inbound connections that match the firewall
                             rule to the instances on the network. The IP
                             address blocks must be specified in CIDR format.
    Raises:
        Exception: Not enough arguments to execute command
    """
    format_service_accounts = ','.join(service_accounts)
    rule_name = rule_name.lower()
    format_rules = ','.join(rules)
    gcloud_command_args = ['gcloud', 'compute', 'firewall-rules', 'create',
                           rule_name, '--action', action.value,
                           '--target-service-accounts',
                           format_service_accounts, '--priority',
                           str(priority), '--direction', direction.value,
                           '--rules', format_rules,
                           '--network', vpc_host_network]
    if source_ranges:
        gcloud_command_args.extend(['--source-ranges', source_ranges])

    return_code, _, err = utils.run_command(gcloud_command_args)
    if return_code:
        print (err)


def enable_os_login(instance_name, zone):
    """Enable os login for the given VM instance.

    Args:
        instance_name (str): Name of the VM instance
        zone (str): Zone of the VM instance
    """
    gcloud_command_args = ['gcloud', 'compute', 'instances', 'add-metadata',
                           instance_name, '--metadata', 'enable-oslogin=TRUE',
                           '--zone', zone]

    return_code, _, err = utils.run_command(gcloud_command_args)
    if return_code:
        print (err)


def create_deployment(project_id,
                      organization_id,
                      deploy_tpl_path,
                      installation_type,
                      timestamp,
                      dry_run):
    """Create the GCP deployment.

    Args:
        project_id (str): GCP project id.
        organization_id (str): GCP organization id.
        deploy_tpl_path (str): Path of deployment template.
        installation_type (str): Type of the installation (client/server).
        timestamp (str): Timestamp.
        dry_run (bool): Whether the installer is in dry run mode.

    Returns:
        str: Name of the deployment.
    """

    if dry_run:
        print('This is a dry run, so skipping this step.')
        return 0

    utils.print_banner('Creating Forseti {} Deployment'.format(
        installation_type.capitalize()))

    # Ping the deployment manager and make sure the API is ready
    utils.run_command(
        ['gcloud', 'deployment-manager', 'deployments', 'list'])

    deployment_name = 'forseti-{}-{}'.format(installation_type,
                                             timestamp)
    print('Deployment name: {}'.format(deployment_name))
    print('Monitor the deployment progress here: '
          'https://console.cloud.google.com/deployments/details/'
          '{}?project={}&organizationId={}\n'.format(
              deployment_name, project_id, organization_id))

    # Start the deployment
    utils.run_command(
        ['gcloud', 'deployment-manager', 'deployments', 'create',
         deployment_name, '--config={}'.format(deploy_tpl_path), '--async'])

    return deployment_name


def check_vm_init_status(vm_name, zone):
    """Check vm initialization status.

    Args:
        vm_name (str): Name of the VM instance.
        zone (str): Zone of the VM instance.

    Returns:
        bool: Whether or not the VM has finished initializing.
    """

    check_script_executed = 'tail -n1 /tmp/deployment.log'

    _, out, _ = utils.run_command(
        ['gcloud', 'compute', 'ssh', vm_name,
         '--zone', zone, '--command', check_script_executed, '--quiet'])
    # --quiet flag is needed to eliminate the prompting for user input
    # which will hang the run_command function
    # i.e. It will create a folder at ~/.ssh and generate a new ssh key

    if 'Execution of startup script finished' in out:
        return True

    return False


def get_domain_from_organization_id(organization_id):
    """Get domain from organization id.

    Args:
        organization_id (str): Id of the organization.

    Returns:
        str: Domain of the org.
    """

    return_code, out, err = utils.run_command(
        ['gcloud', 'organizations', 'describe', organization_id,
         '--format=json'])

    if return_code:
        print(err)
        print('Unable to retrieve domain from the organization.')
        return ''

    org_info = json.loads(out)

    return org_info.get('displayName', '')


def check_deployment_status(deployment_name, status):
    """Check the status of a deployment.

    If there is any error occurred during the deployment, it will
    exit the application.

    Args:
        deployment_name (str): Deployment name.
        status (DeploymentStatus): Status of the deployment.

    Returns:
        bool: Whether or not the deployment status match with the given status.
    """

    return_code, out, err = utils.run_command(
        ['gcloud', 'deployment-manager', 'deployments', 'describe',
         deployment_name, '--format=json'])

    if return_code:
        print(err)
        print(constants.MESSAGE_DEPLOYMENT_ERROR)
        sys.exit(1)

    deployment_info = json.loads(out)

    deployment_operation = deployment_info['deployment']['operation']

    deployment_status = deployment_operation['status']

    deployment_error = deployment_operation.get('error', {})

    if deployment_error:
        print(deployment_error)
        print(constants.MESSAGE_DEPLOYMENT_ERROR)
        sys.exit(1)

    return deployment_status == status.value
