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

"""Utils.

This has been tested with python 2.7.
"""

from __future__ import print_function

import subprocess
import re
import os
import time

from constants import (
    VERSIONFILE_REGEX, FORSETI_SRC_PATH, SERVICE_ACCT_EMAIL_FMT,
    SERVICE_ACCT_FMT)


def id_from_name(name):
    """Extract the id (number) from the resource name.

    Args:
        name (str): The name of the resource, formatted as
            "${RESOURCE_TYPE}/${RESOURCE_ID}".

    Returns:
        str: The resource id.
    """
    if not name or name.index('/') < 0:
        return name
    return name[name.index('/')+1:]


def print_banner(text):
    """Print a banner.

    Args:
        text (str): Text to put in the banner.
    """
    print('')
    print('+-------------------------------------------------------')
    print('|  %s' % text)
    print('+-------------------------------------------------------')
    print('')


def get_forseti_version():
    """Get Forseti version from version file.

    Returns:
        str: The version.
    """
    version = None
    version_re = re.compile(VERSIONFILE_REGEX)
    version_file = os.path.join(
        FORSETI_SRC_PATH, '__init__.py')
    with open(version_file, 'rt') as vfile:
        for line in vfile:
            version_match = version_re.match(line)
            if version_match:
                version = version_match.group(1)
                break
    return version


def get_remote_branches():
    """Get remote git branches.

    Returns:
        list: A list of branches.
    """
    branches = []
    return_code, out, err = run_command(
        ['git', 'branch', '-r'])
    if return_code:
        print(err)
    else:
        out = out.strip()
        if out:
            branches = [b.strip() for b in out.split('\n')]
    return branches


def checkout_git_branch():
    """Let user choose git branch and check it out.

    Returns:
        str: The checked out branch, if exists.
    """
    branches = get_remote_branches()
    choice_index = -1
    while choice_index < 0 or choice_index > len(branches):
        branches = get_remote_branches()
        print('Remote branches:')
        for (i, branch) in enumerate(branches):
            print('[%s] %s' % (i+1, branch[len('origin/'):]))
        try:
            choice_index = int(raw_input(
                'Enter your numerical choice: ').strip())
        except ValueError:
            print('Invalid input choice, try again.')
    branch = branches[choice_index-1][len('origin/'):]
    return_code, _, err = run_command(
        ['git', 'checkout', branch])
    if return_code:
        print(err)
    return branch


def full_service_acct_email(account_id, project_id):
    """Generate the full service account email.

    Args:
        account_id (str): The service account id, i.e. the part before
            the "@".
        project_id (str): The project id the service account belongs to

    Returns:
        str: The full service account email.
    """
    return SERVICE_ACCT_EMAIL_FMT.format(account_id, project_id)


def format_resource_id(resource_type, resource_id):
    """Format the resource id as $RESOURCE_TYPE/$RESOURCE_ID.

    Args:
        resource_type (str): The resource type.
        resource_id (str): The resource id.

    Returns:
        str: The formatted resource id.
    """
    return '%s/%s' % (resource_type, resource_id)


def format_service_acct_id(prefix, modifier, timestamp, project_id):
    """Format the service account ids.

    Args:
        prefix (str): The prefix of the account id
        modifier (str): Access level of the account
        timestamp (str): Timestamp of the class
        project_id (str): Id of the project on GCP

    Returns:
        str: Service account id
    """

    return full_service_acct_email(
        SERVICE_ACCT_FMT.format(prefix, modifier, timestamp), project_id)


def infer_version(advanced_mode):
    """Infer the Forseti version, or ask user to input one not listed.

    Args:
        advanced_mode (bool): Whether or not the installer is in advanced mode

    Returns:
        str: Selected Forseti branch
    """
    return_code, out, err = run_command(
        ['git', 'rev-parse', '--abbrev-ref', 'HEAD'])
    if return_code:
        print(err)
        print('Will try to infer the Forseti version instead.')
    else:
        branch = out.strip()

    user_choice = None
    if not branch or branch == 'master':
        version = get_forseti_version()
        if version:
            branch = 'v%s' % version

    if not advanced_mode:
        user_choice = 'y'

    while user_choice != 'y' and user_choice != 'n':
        user_choice = raw_input(
            'Install Forseti branch/tag %s? (y/n) '
            % branch).lower().strip()

    if user_choice == 'n':
        branch = checkout_git_branch()
        if branch:
            branch = branch
        else:
            print('No branch was chosen; using %s' % branch)

    print('Forseti branch/tag: %s' % branch)
    return branch


def create_deployment(project_id,
                      organization_id,
                      deploy_tpl_path,
                      template_type,
                      datetimestamp,
                      dry_run):
    """Create the GCP deployment.

    Args:
        project_id (str): GCP project id
        organization_id (str): GCP organization id
        deploy_tpl_path (str): Path of deployment template
        template_type (str): Type of the template (client/server)
        datetimestamp (str): Timestamp
        dry_run (bool): Whether the installer is in dry run mode

    Returns:
        str: Name of the deployment
        int: The return code value of running `gcloud` command to create
            the deployment.
    """
    print_banner('Create Forseti deployment')

    if dry_run:
        print('This is a dry run, so skipping this step.')
        return 0

    print ('This may take a few minutes.')
    deployment_name = 'forseti-security-{}-{}'.format(template_type,
                                                      datetimestamp)
    print('Deployment name: {}'.format(deployment_name))
    print('Deployment Manager Dashboard: '
          'https://console.cloud.google.com/deployments/details/'
          '{}?project={}&organizationId={}\n'.format(
              deployment_name, project_id, organization_id))
    return_code, out, err = run_command(
        ['gcloud', 'deployment-manager', 'deployments', 'create',
         deployment_name, '--config={}'.format(deploy_tpl_path)])
    time.sleep(2)
    if return_code:
        print(err)
    else:
        print(out)
        print('\nCreated deployment successfully.')

    return deployment_name, return_code


def run_command(cmd_args):
    """Wrapper to run a command in subprocess.

    Args:
        cmd_args (str): The list of command arguments.

    Returns:
        int: The return code. 0 is "ok", anything else is "error".
        str: Output, if command was successful.
        err: Error output, if there was an error.
    """
    proc = subprocess.Popen(cmd_args,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)
    out, err = proc.communicate()
    return proc.returncode, out, err
