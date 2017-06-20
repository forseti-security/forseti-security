# Copyright 2017 Google Inc.
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

TODO: Write config options to an output file and give option to read in.
"""

from __future__ import print_function

import json
import os
import re
import subprocess
import time

from distutils import spawn


def org_id_from_org_name(org_name):
    """Extract the organization id (number) from the organization name.

    Args:
        org_name(str): The name of the organization, formatted as
            "organizations/${ORGANIZATION_ID}".

    Returns:
    """
    return org_name[len('organizations/'):]


class ForsetiGcpSetup(object):
    """Setup the Forseti Security GCP components."""

    PROJECT_ID_REGEX = re.compile(r'^[a-z][a-z0-9-]{6,30}$')
    REQUIRED_APIS = [
        {'name': 'Cloud SQL',
         'service': 'sql-component.googleapis.com'},
        {'name': 'Cloud SQL Admin',
         'service': 'sqladmin.googleapis.com'},
        {'name': 'Cloud Resource Manager',
         'service': 'cloudresourcemanager.googleapis.com'},
        {'name': 'Admin SDK',
         'service': 'admin.googleapis.com'},
        {'name': 'Deployment Manager',
         'service': 'deploymentmanager.googleapis.com'}]

    ORG_IAM_ROLES = [
        'roles/browser',
        'roles/compute.networkAdmin',
        'roles/editor',
        'roles/iam.securityReviewer',
        'roles/resourcemanager.folderAdmin',
        'roles/storage.admin',
    ]

    SERVICE_ACCT_FMT = '{}@{}.iam.gserviceaccount.com'

    DEFAULT_BUCKET_FORMAT = 'gs://{}-forseti'
    GCS_LS_ERROR_REGEX = re.compile(r'^(.*Exception): (\d{3})', re.MULTILINE)

    DEFAULT_CLOUDSQL_INSTANCE_NAME = 'forseti-security'
    DEFAULT_CLOUDSQL_USER = 'forseti_user'
    CLOUDSQL_DB_VERSION = 'MYSQL_5_7'
    CLOUDSQL_TIER = 'db-n1-standard-1'
    CLOUDSQL_STORAGE_SIZE_GB = '25'
    CLOUDSQL_STORAGE_TYPE = 'SSD'
    CLOUDSQL_ERROR_REGEX = re.compile(r'HTTPError (\d{3}):', re.MULTILINE)

    def __init__(self):
        """Init."""
        self.config_name = None
        self.auth_account = None
        self.organization_id = None
        self.project_id = None
        self.gcp_service_account = None
        self.gsuite_service_account = None
        self.gsuite_svc_acct_key_location = None
        self.rules_bucket_name = None
        self.bucket_location = None
        self.cloudsql_instance = None
        self.cloudsql_user = None
        self.cloudsql_region = None
        self.should_inventory_groups = False

    def __repr__(self):
        """String representation of this instance.

        Returns:
            str: __repr__
        """
        return ('ForsetiGcpSetup:\n'
                '  Account: {}\n'
                '  ProjectId: {}\n'
                .format(self.auth_account,
                        self.project_id))

    def run_setup(self):
        """Run the setup steps."""
        self.ensure_gcloud_installed()
        self.auth_login()
        self.list_organizations()
        self.create_or_use_project()
        self.check_billing()
        self.enable_apis()
        self.create_service_accounts()
        self.grant_gcp_svc_acct_roles()
        self.setup_bucket_name()
        self.setup_cloudsql_name()
        self.setup_cloudsql_user()
        self.generate_deployment_templates()
        self.create_data_storage()
        self.post_install_instructions()

    @staticmethod
    def _print_banner(text):
        """Print a banner.

        Args:
            text (str): Text to put in the banner.

        Returns:
        """
        print('')
        print('+-------------------------------------------------------')
        print('|  %s' % text)
        print('+-------------------------------------------------------')
        print('')

    def ensure_gcloud_installed(self):
        """Check whether gcloud tool is installed.

        Returns:
        """
        self._print_banner('Checking if gcloud is installed')
        gcloud_cmd = spawn.find_executable('gcloud')
        if gcloud_cmd:
            print('gcloud already installed, continue...')
        else:
            raise EnvironmentError(
                'Could not find gcloud. '
                'Have you installed the Google Cloud SDK?\n'
                'You can get it here: https://cloud.google.com/sdk/')

    def auth_login(self):
        """Authenticate with GCP account.

        Returns:
        """
        self._print_banner('Auth GCP account')
        subprocess.call(['gcloud', 'auth', 'login', '--force'])
        proc = subprocess.Popen(
            ['gcloud', 'auth', 'list',
             '--filter=status:ACTIVE', '--format=value(account)'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE)
        out, err = proc.communicate()
        if not proc.returncode:
            print(err)

        if out:
            self.auth_account = out.strip()

    def list_organizations(self):
        """List the available organizations.

        Returns:
        """
        proc = subprocess.Popen(
            ['gcloud', 'organizations', 'list', '--format=json'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE)
        out, _ = proc.communicate()
        if out:
            try:
                orgs = json.loads(out)
                if orgs:
                    self._choose_organization(orgs)
            except ValueError:
                print('Error retrieving organization id')

    def _choose_organization(self, orgs):
        """Choose from a list of organizations.

        Returns:
        """
        self._print_banner('Choose the organization where to deploy Forseti')
        choice = -1
        while True:
            print('Organizations:')
            for i, org in enumerate(orgs):
                print('[%s] %s (%s)' %
                      (i+1,
                       org['displayName'],
                       org_id_from_org_name(org['name'])))
            choice = raw_input('Enter your choice: ').strip()
            try:
                numeric_choice = int(choice)
                if numeric_choice > len(orgs) or numeric_choice < 1:
                    raise ValueError
                else:
                    self.organization_id = org_id_from_org_name(org['name'])
                    break
            except ValueError:
                print('Invalid choice, try again.')

    def create_or_use_project(self):
        """Create a project or enter the id of a project to use.

        Returns:
        """
        project_id = None
        self._print_banner('Setup Forseti project')

        while True:
            project_choice = raw_input(
                'Which project do you want to use for Forseti Security?\n'
                '[1] Existing project\n'
                '[2] Create a new project\n'
                'Enter your choice: ').strip()
            # Only break the loop when input is valid
            if project_choice == '1':
                project_id = self._use_project()
                break
            if project_choice == '2':
                project_id = self._create_project()
                break

        self._set_project(project_id)

    def _create_project(self):
        """Create the project based on user's input.

        If the `projects create` command succeeds, its exit status will
        be 0; however, if it fails, its exit status will be 1.

        Returns:
            str: The project id or None.
        """
        while True:
            project_id = raw_input(
                '\nEnter a project id '
                '(alphanumeric and hyphens): ').strip()
            if self.PROJECT_ID_REGEX.match(project_id):
                proj_create_cmd = [
                    'gcloud', 'projects', 'create', project_id,
                    '--name=%s' % project_id]
                if self.organization_id:
                    proj_create_cmd.append(
                        '--organization=%s' % self.organization_id)
                exit_status = subprocess.call(proj_create_cmd)
                if not exit_status:
                    return project_id
        return None

    def _use_project(self):
        """Verify whether use has access to a project by describing it.

        If the `projects describe` command succeeds, its exit status will
        be 0; however, if it fails, its exit status will be 1.

        Returns:
            str: The project id or None.
        """
        print('\nBe advised! We recommend using a project dedicated to '
              'running Forseti.\n')
        while True:
            project_id = raw_input('\nEnter a project id: ').strip()
            exit_status = subprocess.call(
                ['gcloud', 'projects', 'describe',
                 ('--format=table[box,title="Project"]'
                  '(name,projectId,projectNumber)'),
                 project_id])
            if not exit_status:
                return project_id
        return None

    def _set_project(self, project_id):
        """Save the gcloud configuration for future use.

        Returns:
        """
        print('\nTrying to activate configuration {}...'.format(project_id))
        return_val = subprocess.call(
            ['gcloud', 'config', 'configurations', 'activate', project_id])
        if return_val:
            print('Creating a new configuration for {}...'.format(project_id))
            subprocess.call(
                ['gcloud', 'config', 'configurations', 'create', project_id])
            subprocess.call(
                ['gcloud', 'config', 'set', 'account', self.auth_account])

        proc = subprocess.Popen(
            ['gcloud', 'config', 'set', 'project', project_id],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE)
        _, err = proc.communicate()
        if not proc.returncode:
            print(err)
        self.project_id = project_id

    def check_billing(self):
        """Check whether billing is enabled.

        Poll GCP until billing is enabled.

        Returns:
        """
        print_instructions = True
        self._print_banner('Checking whether billing has been enabled')
        while True:
            billing_proc = subprocess.Popen(
                ['gcloud', 'alpha', 'billing',
                 'accounts', 'projects', 'describe',
                 self.project_id],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE)
            billing_enabled = subprocess.Popen(
                ['grep', 'billingEnabled'],
                stdin=billing_proc.stdout,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE)
            billing_proc.stdout.close()
            out, _ = billing_enabled.communicate()
            if out:
                print('Billing has been enabled for this project, continue...')
                break
            else:
                # Billing has not been enabled, so print instructions
                # and wait/poll for billing to be enabled in the
                # account/project. Once user enables billing, the script
                # will continue.
                if print_instructions:
                    print_instructions = self._print_billing_instructions()
                time.sleep(1)

    def _print_billing_instructions(self):
        """Print billing instructions.

        Returns:
        """
        print(('Before enabling the GCP APIs necessary to run '
               'Forseti Security, you must enable Billing for '
               'this project. Go to the following link:\n\n'
               '    '
               'https://console.cloud.google.com/'
               'billing?project={}\n\n'
               'After you enable billing, setup will continue.\n'
               .format(self.project_id)))
        return False

    def enable_apis(self):
        """Enable necessary APIs for Forseti Security

        1. Cloud SQL
        2. Cloud SQL Admin
        3. Cloud Resource Manager
        4. Admin SDK
        5. Deployment Manager

        Returns:
        """
        self._print_banner('Enabling required APIs')
        for api in self.REQUIRED_APIS:
            print('Enabling the {} API...'.format(api['name']))
            proc = subprocess.Popen(
                    ['gcloud', 'alpha', 'service-management',
                     'enable', api['service']],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE)
            _, err = proc.communicate()
            if not proc.returncode:
                print(err)
            else:
                print('Done.')

    def create_service_accounts(self):
        """Creates the service accounts that will be used by Forseti.

        Returns:
        """
        self._print_banner('Setup service accounts')

        svc_acct_actions = [
            {'usage': 'accessing GCP',
             'acct': 'gcp_service_account',
             'default_name': 'forseti-gcp'},
            {'usage': 'getting GSuite groups',
             'acct': 'gsuite_service_account',
             'default_name': 'forseti-gsuite',
             'skippable': True},
        ]
        for action in svc_acct_actions:
            skippable = action.get('skippable', False)
            skip_text = ''
            if skippable:
                skip_text = '[3] Skip for now\n'
            action_text = (
                'Forseti requires a service account for %s.\n'
                '[1] Use existing service account\n'
                '[2] Create new service account\n'
                '%s'
                'Enter your choice: ' % (action['usage'], skip_text))
            while True:
                svc_acct_choice = raw_input(action_text).strip()
                # Only break the loop when input is valid
                if svc_acct_choice == '1':
                    svc_acct = self._use_svc_acct()
                    break
                if svc_acct_choice == '2':
                    svc_acct = self._create_svc_acct(action['default_name'])
                    break
                if svc_acct_choice == '3' and skippable:
                    print('Skipping service account creation.')
                    break

            self._set_service_account(action['acct'], svc_acct)

            # After setting the service account property, check if
            # the Gsuite service account key needs to be downloaded.
            if svc_acct_choice == '2' and svc_acct and \
               action['acct'] == 'gsuite_service_account':
                self._download_gsuite_svc_acct_key()

    def _use_svc_acct(self):
        """Use an existing service account.

        Returns:
        """
        existing_svc_acct = None
        while not existing_svc_acct:
            existing_svc_acct = raw_input(
                'Enter the full email of the service account '
                'you want to use: ').strip()
            proc = subprocess.Popen(
                ['gcloud', 'iam', 'service-accounts', 'describe',
                 existing_svc_acct],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE)
            _, err = proc.communicate()
            if not proc.returncode:
                print(err)
            else:
                break

        print('\nOk, using existing service account: %s\n' % existing_svc_acct)
        return existing_svc_acct

    def _create_svc_acct(self, default_name):
        """Create a service account.

        Args:
            default_name (str): The default service account name.

        Returns:
            str: The full name of the service account.
        """
        while True:
            new_svc_acct = raw_input(
                'Enter the name for your new service account '
                '(default: %s): ' % default_name).strip().lower()
            if not new_svc_acct:
                new_svc_acct = default_name
            proc = subprocess.Popen(
                ['gcloud', 'iam', 'service-accounts', 'create', new_svc_acct,
                 '--display-name=%s' % new_svc_acct],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE)
            _, err = proc.communicate()
            if not proc.returncode:
                print(err)
            else:
                break
        full_svc_acct = self.SERVICE_ACCT_FMT.format(
            new_svc_acct, self.project_id)

        print('\nCreated new service account: %s\n' % full_svc_acct)
        return full_svc_acct

    def _download_gsuite_svc_acct_key(self):
        """Download the service account key.

        Returns:
        """
        print('Downloading Gsuite service account key for %s'
              % self.gsuite_service_account)
        proc = subprocess.Popen(
            ['gcloud', 'iam', 'service-accounts', 'keys',
             'create', 'gsuite_key.json',
             '--iam-account=%s' % self.gsuite_service_account],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE)
        _, err = proc.communicate()
        if not proc.returncode:
            print(err)

        self.gsuite_svc_acct_key_location = os.path.abspath(
            os.path.join(
                os.path.dirname(__file__),
                'gsuite_key.json'))

    def _set_service_account(self, which_svc_acct, svc_acct):
        """Set the service account.

        Args:
            which_svc_acct (str): Which service account (GCP/Gsuite) to set.
            svc_acct (str): The service account full name.

        Returns:
        """
        setattr(self, which_svc_acct, svc_acct)

    def grant_gcp_svc_acct_roles(self):
        """Grant the following IAM roles to GCP service account.

        Project Browser
        Security Reviewer
        Project Editor
        Resource Manager Folder Admin
        Storage Object Admin
        Compute Network Admin

        Returns:
        """
        self._print_banner('Assigning roles to the GCP service account')
        if not self.organization_id:
            return

        for role in self.ORG_IAM_ROLES:
            iam_role_cmd = [
                'gcloud',
                'organizations',
                'add-iam-policy-binding',
                self.organization_id,
                '--member=serviceAccount:%s' % self.gcp_service_account,
                '--role=%s' % role,
                ]
            print('Assigning %s...' % role)
            proc = subprocess.Popen(iam_role_cmd,
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE)
            _, err = proc.communicate()
            if not proc.returncode:
                print(err)
            else:
                print('Done')

    def setup_bucket_name(self):
        """Ask user to come up with a bucket name for the rules.

        Returns:
        """
        self._print_banner('Setup bucket name')
        default_bucket = self.DEFAULT_BUCKET_FORMAT.format(self.project_id)

        while True:
            bucket_name = raw_input('Enter a bucket name (default: {}): '
                                    .format(default_bucket)).strip().lower()
            if not bucket_name:
                bucket_name = default_bucket

            if not bucket_name.startswith('gs://'):
                bucket_name = 'gs://{}'.format(bucket_name)

            if bucket_name:
                self.rules_bucket_name = bucket_name
                break

    def create_bucket(self):
        """Create the bucket.

        Returns:
        """
        print('Creating bucket...')
        proc = subprocess.Popen(
            ['gsutil', 'mb', self.rules_bucket_name],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE)
        _, err = proc.communicate()
        if not proc.returncode:
            print(err)

    def setup_cloudsql_name(self):
        """Ask user to name their Cloud SQL instance.

        Returns:
        """
        self._print_banner('Setup Cloud SQL name')
        instance_name = raw_input(
                'Enter a name for the Forseti Cloud SQL instance '
                '(default: {}) '.format(self.DEFAULT_CLOUDSQL_INSTANCE_NAME))\
            .strip().lower()
        if not instance_name:
            instance_name = self.DEFAULT_CLOUDSQL_INSTANCE_NAME
        self.cloudsql_instance = instance_name

    def setup_cloudsql_user(self):
        """Ask user to input Cloud SQL user name.

        Returns:
        """
        sql_user = raw_input(
            'Enter the sql user name of your choice '
            '(default: {}) '
            .format(self.DEFAULT_CLOUDSQL_USER)).strip().lower()
        if not sql_user:
            sql_user = self.DEFAULT_CLOUDSQL_USER
        self.cloudsql_user = sql_user

    def create_cloudsql_instance(self):
        """Create Cloud SQL instance.

        Returns:
        """
        if self.cloudsql_instance:
            print('Creating Cloud SQL instance... This will take awhile...')

            proc = subprocess.Popen(
                ['gcloud', 'sql', 'instances', 'create', self.cloudsql_instance,
                 '--database-version=%s' % self.CLOUDSQL_DB_VERSION,
                 '--tier=%s' % self.CLOUDSQL_TIER,
                 '--storage-size=%s' % self.CLOUDSQL_STORAGE_SIZE_GB,
                 '--storage-type=%s' % self.CLOUDSQL_STORAGE_TYPE],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE)
            _, err = proc.communicate()
            if not proc.returncode:
                print(err)

        if self.cloudsql_instance:
            proc = subprocess.Popen(
                ['gcloud', 'sql', 'users', 'create',
                 self.cloudsql_user, 'localhost',
                 '--instance', self.cloudsql_instance],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE)
            _, err = proc.communicate()
            if not proc.returncode:
                print(err)

    def generate_deployment_templates(self):
        """Generate deployment templates.

        Returns:
        """
        # TODO: generate deployment templates
        # TODO: ask if we should create the deployment
        pass

    def create_data_storage(self):
        """Create Cloud SQL instance and Cloud Storage bucket. (optional)

        Returns:
        """
        self._print_banner('Create data storage (optional)')
        should_create_bucket = raw_input(
            'Create Cloud Storage bucket now? (y/N) ').strip().lower()
        if should_create_bucket == 'y':
            self.create_bucket()
        should_create_cloudsql = raw_input(
            'Create Cloud SQL instance now? '
            'This will take awhile. (y/N) ').strip().lower()
        if should_create_cloudsql == 'y':
            self.create_cloudsql_instance()

    def post_install_instructions(self):
        """Show post-install instructions.

        Print link to go to GSuite service account and enable DWD, if GSuite
        service account was created.
        Print link for deployment manager dashboard.

        Returns:
        """
        self._print_banner('Post-setup instructions')

        print('Congratulations! You\'ve completed the Forseti prerequisite '
              'setup.\n')

        if self.gsuite_service_account:
            print('It looks like you created a service account for retrieving '
                  'Gsuite groups. There is just more step to enable the groups '
                  'retrieval.\n'
                  'Please go to the following link: \n'
                  '    '
                  'https://console.cloud.google.com/iam-admin/serviceaccounts'
                  '/project?project=%s&organizationId=%s\n\n'
                  '  1) Look for the service account with ID "%s".\n'
                  '  2) Click the dot menu to show some options.\n'
                  '  3) Click "Edit".\n'
                  '  4) Check the box to "Enable domain-wide-delegation".\n'
                  '  5) Click "Save".\n'
                  '  6) Follow instructions on how to link the service account '
                  'to Gsuite:\n'
                  '    '
                  'PLACEHOLDER FOR LINK ON HOW TO ENABLE SERVICE ACCT FOR '
                  'GSUITE\n\n'
                  '  Your Gsuite service account key has been downloaded to:\n'
                  '    '
                  '%s\n'
                  %
                  (self.project_id,
                   self.organization_id,
                   self.gsuite_service_account,
                   self.gsuite_svc_acct_key_location))

        # TODO: print deployment manager dashboard
