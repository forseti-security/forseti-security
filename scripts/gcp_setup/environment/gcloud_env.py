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

"""Set up Forseti Security on GCP.

This has been tested with python 2.7.
"""
# pylint: disable=too-many-lines
# pylint: disable=too-many-instance-attributes
# pylint: disable=too-many-public-methods

from __future__ import print_function

#import configparser
import datetime
import json
import os
import re
import subprocess
import sys
import time


CONFIG_FILENAME_FMT = 'forseti-setup-{}.cfg'

DEFAULT_BUCKET_FMT = 'gs://{}-data-{}'
DEFAULT_CLOUDSQL_INSTANCE_NAME = 'forseti-security'

GCLOUD_MIN_VERSION = (180, 0, 0)
GCLOUD_VERSION_REGEX = r'Google Cloud SDK (.*)'
GCLOUD_ALPHA_REGEX = r'alpha.*'

SERVICE_ACCT_FMT = 'forseti-{}-{}-{}'
SERVICE_ACCT_EMAIL_FMT = '{}@{}.iam.gserviceaccount.com'

# Roles
GCP_READ_IAM_ROLES = [
    'roles/browser',
    'roles/compute.networkViewer',
    'roles/iam.securityReviewer',
    'roles/appengine.appViewer',
    'roles/bigquery.dataViewer',
    'roles/servicemanagement.quotaViewer',
    'roles/cloudsql.viewer',
]

GCP_WRITE_IAM_ROLES = [
    'roles/compute.securityAdmin',
]

# Required APIs
PROJECT_IAM_ROLES = [
    'roles/storage.objectViewer',
    'roles/storage.objectCreator',
    'roles/cloudsql.client',
    'roles/logging.logWriter',
]

REQUIRED_APIS = [
    {'name': 'Admin SDK',
     'service': 'admin.googleapis.com'},
    {'name': 'AppEngine Admin',
     'service': 'appengine.googleapis.com'},
    {'name': 'Cloud Resource Manager',
     'service': 'cloudresourcemanager.googleapis.com'},
    {'name': 'Cloud SQL',
     'service': 'sql-component.googleapis.com'},
    {'name': 'Cloud SQL Admin',
     'service': 'sqladmin.googleapis.com'},
    {'name': 'Compute Engine',
     'service': 'compute.googleapis.com'},
    {'name': 'Deployment Manager',
     'service': 'deploymentmanager.googleapis.com'},
    {'name': 'IAM',
     'service': 'iam.googleapis.com'},
]

# Org Resource Types
RESOURCE_TYPES = ['organization', 'folder', 'project']

# Paths
ROOT_DIR_PATH = os.path.dirname(
    os.path.dirname(
        os.path.dirname(
            os.path.dirname(__file__))))

FORSETI_SRC_PATH = os.path.join(
    ROOT_DIR_PATH, 'google', 'cloud', 'forseti')

VERSIONFILE_REGEX = r'__version__ = \'(.*)\''


def id_from_name(name, resource_type):
    """Extract the id (number) from the resource name.

    Args:
        name (str): The name of the resource, formatted as
            "${RESOURCE_TYPE}/${RESOURCE_ID}".
        resource_type (str): The resource type.

    Returns:
        str: The resource id.
    """
    return name[len('%s/' % resource_type):]

def org_id_from_org_name(org_name):
    """Extract the organization id (number) from the organization name.

    Args:
        org_name (str): The name of the organization, formatted as
            "organizations/${ORGANIZATION_ID}".

    Returns:
        str: The organization id.
    """
    return id_from_name(org_name, 'organizations')

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
        for line in vfile.readlines():
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
        branches = [b.strip() for b in out.strip().split('\n')]
    return branches

def checkout_git_branch():
    """Let user choose git branch and check it out.

    Returns:
        str: The checked out branch, if exists.
    """
    branch = None
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
        print('You need the following gcloud setup:\n\n'
              'gcloud version >= {}\n'
              'gcloud alpha components\n\n'
              'To install gcloud alpha components: '
              'gcloud components install alpha\n\n'
              'To update gcloud: gcloud components update\n'.
              format('.'.join(
                  [str(i) for i in GCLOUD_MIN_VERSION])))
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

def sanitize_conf_values(conf_values):
    """Sanitize the forseti_conf values not to be zero-length strings.

    Args:
        conf_values (dict): The conf values to replace in the
            forseti_conf.yaml.

    Returns:
        dict: The sanitized values.
    """
    for key in conf_values.keys():
        if not conf_values[key]:
            conf_values[key] = '""'
    return conf_values


class ForsetiGcpSetup(object):
    """Setup the Forseti Security GCP components."""

    def __init__(self, **kwargs):
        """Init.

        Args:
            kwargs (dict): The kwargs.
        """
        self.datetimestamp = datetime.datetime.now().strftime('%Y%m%d%H%M%S')
        self.timestamp = self.datetimestamp[8:]

        self.force_no_cloudshell = bool(kwargs.get('no_cloudshell'))
        self.branch = None
        self.config_filename = (kwargs.get('config') or
                                CONFIG_FILENAME_FMT.format(
                                    self.datetimestamp))

        self.dry_run = bool(kwargs.get('dry_run'))

        self.is_devshell = False
        self.authed_user = None
        self.project_id = None
        self.organization_id = None

        self.access_target = None
        self.target_id = None
        self.resource_root_id = None

        self.enable_write_access = False
        self.user_can_grant_roles = False

        self.gcp_service_account = None
        self.gsuite_service_account = None

        self.bucket_name = None
        self.bucket_location = kwargs.get('gcs_location') or 'us-central1'
        self.cloudsql_instance = '{}-{}'.format(
            DEFAULT_CLOUDSQL_INSTANCE_NAME,
            self.datetimestamp)
        self.cloudsql_region = kwargs.get('cloudsql_region') or 'us-central1'
        self.gce_zone = '{}-c'.format(self.cloudsql_region)

        self.has_roles_script = False

        self.deployment_name = False
        self.deploy_tpl_path = None
        self.forseti_conf_path = None

        # forseti_conf.yaml.in properties
        self.skip_email = False
        self.sendgrid_api_key = kwargs.get('sendgrid_api_key')
        self.notification_sender_email = None
        self.notification_recipient_email = (
            kwargs.get('notification_recipient_email'))
        self.gsuite_superadmin_email = kwargs.get('gsuite_superadmin_email')

    def run_setup(self):
        """Run the setup steps."""
        # Pre-flight checks.
        print_banner('Pre-flight checks')
        self.infer_version()
        check_proper_gcloud()
        self.gcloud_info()
        self.check_cloudshell()
        self.check_authed_user()
        self.check_project_id()
        self.get_organization()
        self.check_billing_enabled()
        self.determine_access_target()
        self.should_enable_write_access()
        self.format_service_acct_ids()
        self.inform_access_on_target()

        enable_apis(self.dry_run)
        self.create_reuse_service_acct('gcp_service_account')
        self.create_reuse_service_acct('gsuite_service_account')

        # Generate names and config.
        print_banner('Generate configs')
        self.generate_bucket_name()
        self.get_email_settings()
        self.generate_forseti_conf()
        self.generate_deployment_templates()

        # Actual deployment.
        # 1. Create deployment.
        # 2. If fails, continue to next step.
        # 3. Otherwise, copy configs (forseti_conf.yaml, rules) to bucket.
        # 4. Grant service account roles.
        # 5. Poll the Forseti VM until it responds, then scp the key.
        return_code = self.create_deployment()
        if not return_code:
            self.copy_config_to_bucket()
            self.grant_gcp_svc_acct_roles()

        self.post_install_instructions(deploy_success=(not return_code))

    def infer_version(self):
        """Infer the Forseti version, or ask user to input one not listed."""
        return_code, out, err = run_command(
            ['git', 'rev-parse', '--abbrev-ref', 'HEAD'])
        if return_code:
            print(err)
            print('Will try to infer the Forseti version instead.')
        else:
            self.branch = out.strip()

        if not self.branch or self.branch == 'master':
            version = get_forseti_version()
            if version:
                self.branch = 'v%s' % version

        user_choice = None
        while user_choice != 'y' and user_choice != 'n':
            user_choice = raw_input(
                'Install Forseti branch/tag %s? (y/n) '
                % self.branch).lower().strip()

        if user_choice == 'n':
            branch = checkout_git_branch()
            if branch:
                self.branch = branch
            else:
                print('No branch was chosen; using %s' % self.branch)

        print('Forseti branch/tag: %s' % self.branch)

    def gcloud_info(self):
        """Read gcloud info, and check if running in Cloud Shell."""
        # Read gcloud info
        return_code, out, err = run_command(
            ['gcloud', 'info', '--format=json'])
        if return_code:
            print(err)
            sys.exit(1)
        else:
            try:
                gcloud_info = json.loads(out)
                config = gcloud_info.get('config', {})
                self.project_id = config.get('project')
                self.authed_user = config.get('account')
                props = config.get('properties', {})
                metrics = props.get('metrics', {})
                self.is_devshell = metrics.get('environment') == 'devshell'
                print('Read gcloud info successfully')
            except ValueError as verr:
                print(verr)
                sys.exit(1)

    def check_cloudshell(self):
        """Check whether using Cloud Shell or bypassing Cloud Shell."""
        if not self.force_no_cloudshell:
            if not self.is_devshell:
                print('Forseti highly recommends running this setup within '
                      'Cloud Shell. If you would like to run the setup '
                      'outside Cloud Shell, please be sure to do the '
                      'following:\n\n'
                      '1) Create a project.\n'
                      '2) Enable billing for the project.\n'
                      '3) Install gcloud and authenticate your account using '
                      '"gcloud auth login".\n'
                      '4) Set your project using '
                      '"gcloud config project set <PROJECT_ID>".\n'
                      '5) Run this setup again, with the --no-cloudshell flag, '
                      'i.e.\n\n    python setup_forseti.py --no-cloudshell\n')
                sys.exit(1)
            else:
                print('Using Cloud Shell, continuing...')
        else:
            print('Bypass Cloud Shell check, continuing...')

    def check_authed_user(self):
        """Get the current authed user."""
        if not self.authed_user:
            print('Error getting authed user. You may need to run '
                  '"gcloud auth login". Exiting.')
            sys.exit(1)
        print('You are: {}'.format(self.authed_user))

    def check_project_id(self):
        """Get the project."""
        if not self.project_id:
            print('You need to have an active project! Exiting.')
            sys.exit(1)
        print('Project id: %s' % self.project_id)

    def check_billing_enabled(self):
        """Check if billing is enabled."""
        return_code, out, err = run_command(
            ['gcloud', 'alpha', 'billing', 'projects', 'describe',
             self.project_id, '--format=json'])
        if return_code:
            print(err)
            self._billing_not_enabled()
        try:
            billing_info = json.loads(out)
            if billing_info.get('billingEnabled'):
                print('Billing IS enabled.')
            else:
                self._billing_not_enabled()
        except ValueError:
            self._billing_not_enabled()

    def _billing_not_enabled(self):
        """Print message and exit."""
        print('\nIt seems that billing is not enabled for your project. '
              'You can check whether billing has been enabled in the '
              'Cloud Platform Console:\n\n'
              '    https://console.cloud.google.com/billing/linkedaccount?'
              'project={}&organizationId={}\n\n'
              'Once you have enabled billing, re-run this setup.\n'.format(
                  self.project_id, self.organization_id))
        sys.exit(1)

    def determine_access_target(self):
        """Determine where to enable Forseti access.

        Either org, folder, or project level.
        """
        print_banner('Forseti access target')
        choices = RESOURCE_TYPES
        choice_index = -1
        while not self.target_id:
            try:
                print('Forseti can be configured to access an organization, '
                      'folder, or project.')
                for (i, choice) in enumerate(choices):
                    print('[%s] %s' % (i+1, choice))
                choice_input = raw_input(
                    'At what level do you want to enable Forseti '
                    'read (and optionally write) access? ').strip()
                choice_index = int(choice_input)
            except ValueError:
                print('Invalid choice, try again.')
                continue

            if choice_index and choice_index <= len(choices):
                self.access_target = choices[choice_index-1]
                if self.access_target == 'organization':
                    self.choose_organization()
                elif self.access_target == 'folder':
                    self.choose_folder()
                else:
                    self.choose_project()

        self.resource_root_id = format_resource_id(
            '%ss' % self.access_target, self.target_id)

        print('Forseti will be granted access to: %s' %
              self.resource_root_id)

    def choose_organization(self):
        """Allow user to input organization id."""
        while not self.target_id:
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
                return

            print('\nHere are the organizations you have access to:')
            for org in orgs:
                print('ID=%s (description="%s")' %
                      (org_id_from_org_name(org['name']), org['displayName']))

            choice = raw_input('Enter the organization id where '
                               'you want Forseti to crawl for data: ').strip()
            try:
                # make sure that the choice is an int before converting to str
                self.target_id = str(int(choice))
            except ValueError:
                print('Invalid choice %s, try again' % choice)

    def choose_folder(self):
        """Allow user to input folder id."""
        while not self.target_id:
            choice = raw_input(
                'Enter the folder id where you want '
                'Forseti to crawl for data: ').strip()
            try:
                # make sure that the choice is an int before converting to str
                self.target_id = str(int(choice))
            except ValueError:
                print('Invalid choice %s, try again' % choice)

    def choose_project(self):
        """Allow user to input project id."""
        while not self.target_id:
            self.target_id = raw_input(
                'Enter the project id (NOT PROJECT NUMBER), '
                'where you want Forseti to crawl for data: ').strip()

    def get_organization(self):
        """Infer the organization from the project's parent."""
        return_code, out, err = run_command(
            ['gcloud', 'projects', 'describe',
             self.project_id, '--format=json'])
        if return_code:
            print(err)
            print('Error trying to find current organization from '
                  'project! Exiting.')
            sys.exit(1)

        try:
            project = json.loads(out)
            project_parent = project.get('parent')
            if not project_parent:
                self._no_organization()
            parent_type = project_parent['type']
            parent_id = project_parent['id']
        except ValueError:
            print('Error retrieving organization id')
            self._no_organization()

        if parent_type == 'folder':
            self._find_org_from_folder(parent_id)
        elif parent_type == 'organization':
            self.organization_id = parent_id
        else:
            self._no_organization()
        if self.organization_id:
            print('Organization id: %s' % self.organization_id)

    @staticmethod
    def _no_organization():
        """No organization, so print a message and exit."""
        print('You need to have an organization set up to use Forseti. '
              'Refer to the following documentation for more information.\n\n'
              'https://cloud.google.com/resource-manager/docs/'
              'creating-managing-organization')
        sys.exit(1)

    def _find_org_from_folder(self, folder_id):
        """Find the organization from some folder.

        Args:
            folder_id (str): The folder id, just a number.
        """
        parent_type = 'folders'
        parent_id = folder_id
        while parent_type != 'organizations':
            return_code, out, err = run_command(
                ['gcloud', 'alpha', 'resource-manager', 'folders',
                 'describe', parent_id, '--format=json'])
            if return_code:
                print(err)
                self._no_organization()
            try:
                folder = json.loads(out)
                parent_type, parent_id = folder['parent'].split('/')
                print('Check parent: %s' % folder['parent'])
            except ValueError as verr:
                print(verr)
                self._no_organization()
        self.organization_id = parent_id

    def should_enable_write_access(self):
        """Ask if user wants to enable write access for Forseti."""
        print_banner('Enable Forseti write access')
        choice = None
        while choice != 'y' and choice != 'n':
            choice = raw_input(
                'Enable write access for Forseti? '
                'This allows Forseti to make changes to policies '
                '(e.g. for Enforcer) (y/n) ').strip().lower()

        if choice == 'y':
            self.enable_write_access = True

    def format_service_acct_ids(self):
        """Format the service account ids."""
        modifier = 'reader'
        if self.enable_write_access:
            modifier = 'readwrite'

        self.gcp_service_account = full_service_acct_email(
            SERVICE_ACCT_FMT.format('gcp', modifier, self.timestamp),
            self.project_id)

        self.gsuite_service_account = full_service_acct_email(
            SERVICE_ACCT_FMT.format('gsuite', 'reader', self.timestamp),
            self.project_id)

    def inform_access_on_target(self):
        """Inform user that they need IAM access to grant Forseti access."""
        print_banner('Current IAM access')
        choice = None
        while choice != 'y' and choice != 'n':
            choice = raw_input('Do you have access to grant Forseti IAM '
                               'roles on the target %s? (y/n) ' %
                               self.resource_root_id).strip().lower()

        if choice == 'y':
            self.user_can_grant_roles = True
            print('Ok, will attempt to grant roles on the target %s.' %
                  self.resource_root_id)
        else:
            self.user_can_grant_roles = False
            print('Will NOT attempt to grant roles on the target %s.' %
                  self.resource_root_id)

    def create_reuse_service_acct(self, acct_type):
        """Create or reuse service account.

        Args:
            acct_type (str): The account type.
        """
        print_banner('Create/Reuse %s' % acct_type)

        choices = ['Create %s' % acct_type, 'Reuse %s' % acct_type]
        choice_index = -1
        while True:
            for (i, choice) in enumerate(choices):
                print('[%s] %s' % (i+1, choice))

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

        # If the choice is "Create service account", create the service
        # account. The default is to create the service account with a 
        # generated name.
        # Otherwise, present the user with options to choose from
        # available service accounts in this project.
        if choice_index == 1:
            new_acct_id = getattr(self, acct_type)
            return_code, out, err = run_command(
                ['gcloud', 'iam', 'service-accounts', 'create',
                 new_acct_id[:new_acct_id.index('@')]])
            if return_code:
                print(err)
                print('Could not create the service account. Terminating '
                      'because this is an unexpected error.')
                sys.exit(1)
        else:
            svc_accts = []
            return_code, out, err = run_command(
                ['gcloud', 'iam', 'service-accounts', 'list', '--format=json'])
            if return_code:
                print(err)
                print('Could not determine the service accounts, will just '
                      'create a new service account.')
                return
            else:
                try:
                    svc_accts = json.loads(out)
                except ValueError:
                    print('Could not determine the service accounts, will just '
                          'create a new service account.')
                    return

            acct_idx = -1
            while acct_idx < 1 or acct_idx > len(svc_accts):
                for (i, acct) in enumerate(svc_accts):
                    print('[%s] %s (%s)' %
                          (i+1, acct['displayName'], acct['email']))

                choice_input = raw_input(
                    'Enter the number of your choice: ').strip()

                try:
                    acct_idx = int(choice_input)
                except ValueError:
                    print('Invalid choice, try again')

            setattr(self, acct_type, svc_accts[acct_idx-1]['email'])

        print('Using %s for %s' % (getattr(self, acct_type), acct_type))

    def grant_gcp_svc_acct_roles(self):
        """Grant the following IAM roles to GCP service account.

        Org/Folder/Project:
            AppEngine App Viewer
            Cloud SQL Viewer
            Network Viewer
            Project Browser
            Security Reviewer
            Service Management Quota Viewer
            Security Admin

        Project:
            Cloud SQL Client
            Storage Object Viewer
            Storage Object Creator
        """
        print_banner('Assigning roles to the GCP service account')
        access_target_roles = GCP_READ_IAM_ROLES
        if self.enable_write_access:
            access_target_roles.extend(GCP_WRITE_IAM_ROLES)

        roles = {
            '%ss' % self.access_target: access_target_roles,
            'projects': PROJECT_IAM_ROLES
        }

        # Keep track of the roles that user couldn'tgrant.
        assign_roles_cmds = []

        for (resource_type, roles) in roles.iteritems():
            if resource_type == 'organizations':
                resource_args = ['organizations']
            elif resource_type == 'folders':
                resource_args = ['alpha', 'resource-manager', 'folders']
            else:
                resource_args = ['projects']

            for role in roles:
                iam_role_cmd = ['gcloud']
                iam_role_cmd.extend(resource_args)
                iam_role_cmd.extend([
                    'add-iam-policy-binding',
                    self.target_id,
                    '--member=serviceAccount:%s' % (
                        self.gcp_service_account),
                    '--role=%s' % role,
                ])
                if self.user_can_grant_roles and not self.dry_run:
                    print('Assigning %s on %s...' % (role, self.target_id))
                    proc = subprocess.Popen(iam_role_cmd,
                                            stdout=subprocess.PIPE,
                                            stderr=subprocess.PIPE)
                    _, err = proc.communicate()
                    if proc.returncode:
                        print(err)
                        assign_roles_cmds.append(iam_role_cmd)
                    else:
                        print('Done.')
                else:
                    assign_roles_cmds.append(iam_role_cmd)

        if assign_roles_cmds:
            print('One or more roles could not be assigned. Writing a '
                  'script with the commands to assign those roles. Please '
                  'give this script to someone (like an admin) who can '
                  'assign these roles for you. If you do not assign these '
                  'roles, Forseti may not work properly!')
            self.has_roles_script = True
            with open('grant_forseti_roles.sh', 'wt') as roles_script:
                roles_script.write('#!/bin/bash\n\n')
                for cmd in assign_roles_cmds:
                    roles_script.write('%s\n' % ' '.join(cmd))

    def generate_bucket_name(self):
        """Generate bucket name for the rules."""
        self.bucket_name = DEFAULT_BUCKET_FMT.format(
            self.project_id, self.timestamp)

    def generate_deployment_templates(self):
        """Generate deployment templates."""
        print('Generate Deployment Manager templates...')

        # Deployment template in file
        deploy_tpl_path = os.path.abspath(
            os.path.join(
                ROOT_DIR_PATH,
                'deployment-templates',
                'deploy-forseti.yaml.in'))
        out_tpl_path = os.path.abspath(
            os.path.join(
                ROOT_DIR_PATH,
                'deployment-templates',
                'deploy-forseti-{}.yaml'.format(self.datetimestamp)))

        deploy_values = {
            'CLOUDSQL_REGION': self.cloudsql_region,
            'CLOUDSQL_INSTANCE_NAME': self.cloudsql_instance,
            'SCANNER_BUCKET': self.bucket_name[len('gs://'):],
            'BUCKET_LOCATION': self.bucket_location,
            'SERVICE_ACCOUNT_GCP': self.gcp_service_account,
            'SERVICE_ACCOUNT_GSUITE': self.gsuite_service_account,
            'BRANCH_OR_RELEASE': 'branch-name: "{}"'.format(self.branch),
            'GSUITE_ADMIN_EMAIL': self.gsuite_superadmin_email,
            'ROOT_RESOURCE_ID': self.resource_root_id,
        }

        # Create Deployment template with values filled in.
        with open(deploy_tpl_path, 'r') as in_tmpl:
            tmpl_contents = in_tmpl.read()
            out_contents = tmpl_contents.format(**deploy_values)
            with open(out_tpl_path, 'w') as out_tmpl:
                out_tmpl.write(out_contents)
                self.deploy_tpl_path = out_tpl_path

        print('\nCreated a deployment template:\n    %s\n' %
              self.deploy_tpl_path)

    def generate_forseti_conf(self):
        """Generate Forseti conf file."""
        # Create a forseti_conf_$TIMESTAMP.yaml config file with
        # values filled in.
        # forseti_conf.yaml in file
        print('Generate forseti_conf_%s.yaml...\n' % self.datetimestamp)
        forseti_conf_in = os.path.abspath(
            os.path.join(
                ROOT_DIR_PATH, 'configs', 'forseti_conf.yaml.in'))
        forseti_conf_gen = os.path.abspath(
            os.path.join(
                ROOT_DIR_PATH, 'configs',
                'forseti_conf_%s.yaml' % self.datetimestamp))

        conf_values = sanitize_conf_values({
            'EMAIL_RECIPIENT': self.notification_recipient_email,
            'EMAIL_SENDER': self.notification_sender_email,
            'SENDGRID_API_KEY': self.sendgrid_api_key,
            'SCANNER_BUCKET': self.bucket_name[len('gs://'):],
            'DOMAIN_SUPER_ADMIN_EMAIL': self.gsuite_superadmin_email,
            'ENABLE_GROUP_SCANNER': 'true',
        })

        with open(forseti_conf_in, 'rt') as in_tmpl:
            tmpl_contents = in_tmpl.read()
            out_contents = tmpl_contents.format(**conf_values)
            with open(forseti_conf_gen, 'w') as out_tmpl:
                out_tmpl.write(out_contents)
                self.forseti_conf_path = forseti_conf_gen

        print('\nCreated forseti_conf_%s.yaml config file:\n    %s\n' %
              (self.datetimestamp,
               self.forseti_conf_path))

    def get_email_settings(self):
        """Ask user for specific setup values."""
        if not self.sendgrid_api_key:
            # Ask for SendGrid API Key
            print('Forseti can send email notifications through SendGrid '
                  'via an API key. '
                  'This step is optional and can be configured later.')
            self.sendgrid_api_key = raw_input(
                'What is your SendGrid API key? '
                '(press [enter] to skip) ').strip()
        if self.sendgrid_api_key:
            self.notification_sender_email = 'forseti-notify@localhost.domain'

            # Ask for notification recipient email
            if not self.notification_recipient_email:
                self.notification_recipient_email = raw_input(
                    'At what email address do you want to receive '
                    'notifications? (press [enter] to skip) ').strip()
        else:
            self.skip_email = True

        if not self.gsuite_superadmin_email:
            # Ask for G Suite super admin email
            print('\nTo read G Suite Groups data, for example, if you want to '
                  'use IAM Explain, please provide a G Suite super admin '
                  'email address. '
                  'This step is optional and can be configured later.')
            self.gsuite_superadmin_email = raw_input(
                'What is your organization\'s G Suite super admin email? '
                '(press [enter] to skip) ').strip()

    def create_deployment(self):
        """Create the GCP deployment.

        Returns:
            int: The return code value of running `gcloud` command to create
                the deployment.
        """
        print_banner('Create Forseti deployment')

        if self.dry_run:
            print('This is a dry run, so skipping this step.')
            return 0

        print ('This may take a few minutes.')
        self.deployment_name = 'forseti-security-{}'.format(self.datetimestamp)
        print('Deployment name: %s' % self.deployment_name)
        print('Deployment Manager Dashboard: '
              'https://console.cloud.google.com/deployments/details/'
              '{}?project={}&organizationId={}\n'.format(
                  self.deployment_name, self.project_id, self.organization_id))
        return_code, out, err = run_command(
            ['gcloud', 'deployment-manager', 'deployments', 'create',
             self.deployment_name, '--config={}'.format(self.deploy_tpl_path)])
        time.sleep(2)
        if return_code:
            print(err)
        else:
            print(out)
            print('\nCreated deployment successfully.')

        return return_code

    def copy_config_to_bucket(self):
        """Copy the config to the created bucket.

        Returns:
            bool: True if copy config succeeded, otherwise False.
            bool: True if copy rules succeeded, otherwise False.
        """
        copy_config_ok = False
        copy_rules_ok = False

        print_banner('Copy configs to bucket')

        if self.dry_run:
            print('This is a dry run, so skipping this step.')
            return False, False

        print('Copy forseti_conf.yaml to {}'.format(self.bucket_name))
        return_code, out, err = run_command(
            ['gsutil', 'cp', self.forseti_conf_path,
             '{}/configs/forseti_conf.yaml'.format(self.bucket_name)])
        if return_code:
            print(err)
        else:
            print(out)
            copy_config_ok = True

        rules_dir = os.path.abspath(
            os.path.join(
                ROOT_DIR_PATH, 'rules'))
        print('Copy rules to {}'.format(self.bucket_name))
        return_code, out, err = run_command(
            ['gsutil', 'cp', '-r', rules_dir, self.bucket_name])
        if return_code:
            print(err)
        else:
            print(out)
            copy_rules_ok = True

        return copy_config_ok, copy_rules_ok

    def post_install_instructions(self, deploy_success):
        """Show post-install instructions.

        Print link for deployment manager dashboard.
        Print link to go to G Suite service account and enable DWD.

        Args:
            deploy_success (bool): Whether deployment was successful.
        """
        print_banner('Post-setup instructions')

        if self.dry_run:
            print('This was a dry run, so a deployment was not attempted. '
                  'You can still create the deployment manually.\n')
        elif deploy_success:
            print('Forseti Security (branch/version: %s) has been '
                  'deployed to GCP.\n' % self.branch)
        else:
            print('Your deployment had some issues. Please review the error '
                  'messages. If you need help, please either file an issue '
                  'on our Github Issues or email '
                  'discuss@forsetisecurity.org.\n')

        print('Your generated Deployment Manager template can be '
              'found here:\n\n    {}\n\n'.format(self.deploy_tpl_path))

        if self.dry_run:
            print('A default configuration file (configs/forseti_conf_%s.yaml) '
                  'has been generated. After you create your deployment, copy '
                  'this file to the bucket created in the deployment:\n\n'
                  '    gsutil cp forseti_conf_%s.yaml '
                  '%s/configs/forseti_conf.yaml\n\n' %
                  (self.datetimestamp,
                   self.bucket_name,
                   self.datetimestamp))
        else:
            print('You can view the details of your deployment in the '
                  'Cloud Console:\n\n    '
                  'https://console.cloud.google.com/deployments/details/'
                  '{}?project={}&organizationId={}\n\n'.format(
                      self.deployment_name,
                      self.project_id,
                      self.organization_id))

            print('A default configuration file (configs/forseti_conf_{}.yaml) '
                  'has been generated. If you wish to change your '
                  'Forseti configuration or rules, e.g. enabling G Suite '
                  'Groups collection, either download the conf file in '
                  'your bucket `{}` or edit your local copy, then follow '
                  'the guide below to copy the files to Cloud Storage:\n\n'
                  '    http://forsetisecurity.org/docs/howto/deploy/'
                  'gcp-deployment.html#move-configuration-to-gcs\n\n'.format(
                      self.datetimestamp,
                      self.bucket_name))

        if self.has_roles_script:
            print('Some roles could not be assigned to %s where you want '
                  'to grant Forseti access. A script `grant_forseti_roles.sh` '
                  'has been generated with the necessary commands to assign '
                  'those roles. Please run this script to assign the Forseti '
                  'roles so that Forseti will work properly.\n\n' %
                  self.resource_root_id)

        if self.skip_email:
            print('If you would like to enable email notifications via '
                  'SendGrid, please refer to:\n\n'
                  '    '
                  'http://forsetisecurity.org/docs/howto/configure/'
                  'email-notification\n\n')

        if self.gsuite_superadmin_email:
            print('To complete setup for G Suite Groups data collection, '
                  'follow the steps in the guide below:\n\n'
                  '    '
                  'http://forsetisecurity.org/docs/howto/configure/'
                  'gsuite-group-collection\n\n')
        else:
            print('If you want to enable G Suite Groups collection in '
                  'Forseti, for example, to use IAM Explain), follow '
                  ' the steps in the guide below:\n\n'
                  '    '
                  'http://forsetisecurity.org/docs/howto/configure/'
                  'gsuite-group-collection\n\n')
