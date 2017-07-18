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

import datetime
import json
import os
import re
import subprocess
import time

from distutils import spawn

# pylint: disable=no-self-use


def org_id_from_org_name(org_name):
    """Extract the organization id (number) from the organization name.

    Args:
        org_name(str): The name of the organization, formatted as
            "organizations/${ORGANIZATION_ID}".

    Returns:
        org_name(str): just the organization_id.
    """
    return org_name[len('organizations/'):]

# pylint: disable=too-many-instance-attributes
class ForsetiGcpSetup(object):
    """Setup the Forseti Security GCP components."""

    PROJECT_ID_REGEX = re.compile(r'^[a-z][a-z0-9-]{6,30}$')
    REQUIRED_APIS = [
        {'name': 'Admin SDK',
         'service': 'admin.googleapis.com'},
        {'name': 'Cloud SQL',
         'service': 'sql-component.googleapis.com'},
        {'name': 'Cloud SQL Admin',
         'service': 'sqladmin.googleapis.com'},
        {'name': 'Cloud Resource Manager',
         'service': 'cloudresourcemanager.googleapis.com'},
        {'name': 'Compute Engine',
         'service': 'compute-component.googleapis.com'},
        {'name': 'Deployment Manager',
         'service': 'deploymentmanager.googleapis.com'},
    ]

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
    BUCKET_REGIONS = [
        {'desc': 'Asia Pacific', 'region': 'Multi-Region', 'value': 'asia'},
        {'desc': 'Europe', 'region': 'Multi-Region', 'value': 'eu'},
        {'desc': 'United States', 'region': 'Multi-Region', 'value': 'us'},

        {'desc': 'Iowa', 'region': 'Americas', 'value': 'us-central1'},
        {'desc': 'South Carolina', 'region': 'Americas', 'value': 'us-east1'},
        {'desc': 'Northern Virginia', 'region': 'Americas',
         'value': 'us-east4'},
        {'desc': 'Oregon', 'region': 'Americas', 'value': 'us-west1'},

        {'desc': 'Taiwan', 'region': 'Asia-Pacific', 'value': 'asia-east1'},
        {'desc': 'Tokyo', 'region': 'Asia-Pacific', 'value': 'asia-northeast1'},
        {'desc': 'Singapore', 'region': 'Asia-Pacific',
         'value': 'asia-southeast1'},

        {'desc': 'Belgium', 'region': 'Europe', 'value': 'europe-west1'},
        {'desc': 'London', 'region': 'Europe', 'value': 'europe-west2'},
    ]

    DEFAULT_CLOUDSQL_INSTANCE_NAME = 'forseti-security'
    DEFAULT_CLOUDSQL_USER = 'forseti_user'
    CLOUDSQL_DB_VERSION = 'MYSQL_5_7'
    CLOUDSQL_TIER = 'db-n1-standard-1'
    CLOUDSQL_STORAGE_SIZE_GB = '25'
    CLOUDSQL_STORAGE_TYPE = 'SSD'
    CLOUDSQL_ERROR_REGEX = re.compile(r'HTTPError (\d{3}):', re.MULTILINE)
    CLOUDSQL_REGIONS = [
        {'desc': 'Iowa', 'region': 'Americas', 'value': 'us-central1'},
        {'desc': 'South Carolina', 'region': 'Americas', 'value': 'us-east1'},
        {'desc': 'Northern Virginia', 'region': 'Americas',
         'value': 'us-east4'},
        {'desc': 'Oregon', 'region': 'Americas', 'value': 'us-west1'},

        {'desc': 'Taiwan', 'region': 'Asia-Pacific', 'value': 'asia-east1'},
        {'desc': 'Tokyo', 'region': 'Asia-Pacific', 'value': 'asia-northeast1'},

        {'desc': 'Belgium', 'region': 'Europe', 'value': 'europe-west1'},
        {'desc': 'London', 'region': 'Europe', 'value': 'europe-west2'},
    ]

    BRANCH_RELEASE_FMT = '{}: "{}"'
    ROOT_DIR_PATH = os.path.dirname(
        os.path.dirname(
            os.path.dirname(
                os.path.dirname(__file__))))

    def __init__(self, **kwargs):
        """Init.

        Args:
            kwargs (dict): The kwargs.
        """
        self.branch = kwargs.get('branch')
        self.version = kwargs.get('version')

        self.config_name = None
        self.auth_account = None
        self.organization_id = None
        self.unassigned_roles = []

        self.project_id = None
        self.gcp_service_account = None
        self.gsuite_service_account = None
        self.gsuite_svc_acct_key_location = None
        self.rules_bucket_name = None
        self.bucket_region = None
        self.cloudsql_instance = None
        self.cloudsql_user = None
        self.cloudsql_region = None
        self.created_deployment = False
        self.deploy_tpl_path = None

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
        if not self.created_deployment:
            self.create_data_storage()
        self.post_install_instructions()

    @staticmethod
    def _print_banner(text):
        """Print a banner.

        Args:
            text (str): Text to put in the banner.
        """
        print('')
        print('+-------------------------------------------------------')
        print('|  %s' % text)
        print('+-------------------------------------------------------')
        print('')

    def ensure_gcloud_installed(self):
        """Check whether gcloud tool is installed.

            Raises:
                EnvironmentError: When `gcloud` can't be found.
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
        """Authenticate with GCP account."""
        self._print_banner('Auth GCP account')
        subprocess.call(['gcloud', 'auth', 'login', '--force'])
        proc = subprocess.Popen(
            ['gcloud', 'auth', 'list',
             '--filter=status:ACTIVE', '--format=value(account)'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE)
        out, err = proc.communicate()
        if proc.returncode:
            print(err)

        if out:
            self.auth_account = out.strip()

    def list_organizations(self):
        """List the available organizations."""
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

        Args:
            orgs(dict): A dictionary of orgs from gcloud.
        """
        if not orgs:
            self._print_banner('No organizations found. Exiting.')

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
                    self.organization_id = org_id_from_org_name(
                        orgs[numeric_choice-1]['name'])
                    break
            except ValueError:
                print('Invalid choice, try again.')

    def create_or_use_project(self):
        """Create a project or enter the id of a project to use."""
        project_id = None
        self._print_banner('Setup Forseti project')

        while True:
            project_choice = raw_input(
                'Which project do you want to use for Forseti Security?\n'
                '[1] Create new project (recommended)\n'
                '[2] Existing project\n'
                'Enter your choice: ').strip()
            if project_choice == '1':
                project_id = self._create_project()
            if project_choice == '2':
                project_id = self._use_project()
            if project_id:
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
                '\nEnter a project id (alphanumeric and hyphens): ').strip()
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
            project_id = raw_input(
                '\nEnter a project id or press [enter] to cancel: ').strip()
            if not project_id:
                break
            proc = subprocess.Popen(
                ['gcloud', 'projects', 'describe',
                 ('--format=table[box,title="Project"]'
                  '(name,projectId,projectNumber)'),
                 project_id],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE)
            _, _ = proc.communicate()
            if proc.returncode:
                print('Invalid project id, please try again.')
            else:
                return project_id
        return None

    def _set_project(self, project_id):
        """Save the gcloud configuration for future use.

        Args:
            project_id (str): A string representation of the GCP projectid.
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
        if proc.returncode:
            print(err)
        self.project_id = project_id

    def check_billing(self):
        """Check whether billing is enabled.

            Poll GCP until billing is enabled.
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
            billing_proc.stderr.close()
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
        """Print billing instructions."""
        print(('Before enabling the GCP APIs necessary to run '
               'Forseti Security, you must enable Billing for '
               'this project. Go to the following link:\n\n'
               '    '
               'https://console.cloud.google.com/'
               'billing?project={}\n\n'
               'After you enable billing, setup will continue.\n'
               'If you think you made a mistake, press Ctrl-C to exit, then '
               're-run this script to start over.\n'
               .format(self.project_id)))

    def enable_apis(self):
        """Enable necessary APIs for Forseti Security.

            1. Cloud SQL
            2. Cloud SQL Admin
            3. Cloud Resource Manager
            4. Admin SDK
            5. Deployment Manager
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
            if proc.returncode:
                print(err)
            else:
                print('Done.')

    def create_service_accounts(self):
        """Creates the service accounts that will be used by Forseti."""
        self._print_banner('Setup service accounts')

        svc_acct_actions = [
            {'usage': 'accessing GCP.',
             'acct': 'gcp_service_account',
             'default_name': 'forseti-gcp'},
            {'usage': ('getting GSuite groups. This should be a different '
                       'service account from the one you are using for '
                       'accessing GCP.'),
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
                'Forseti requires a service account for %s\n'
                '[1] Use existing service account\n'
                '[2] Create new service account\n'
                '%s'
                'Enter your choice: ' % (action['usage'], skip_text))
            while True:
                svc_acct_choice = raw_input(action_text).strip()
                # Only break the loop when input is valid
                if svc_acct_choice == '1':
                    svc_acct = self._use_svc_acct(action['acct'])
                if svc_acct_choice == '2':
                    svc_acct = self._create_svc_acct(action['default_name'])
                if svc_acct_choice == '3' and skippable:
                    print('Skipping service account creation.')
                    break
                if svc_acct:
                    self._set_service_account(action['acct'], svc_acct)
                    break

            # After setting the service account property, check if
            # the GSuite service account key needs to be downloaded.
            # Only download the key if the service account was created.
            if svc_acct_choice == '2' and self.gsuite_service_account and \
               action['acct'] == 'gsuite_service_account':
                self._download_gsuite_svc_acct_key()

    def _use_svc_acct(self, svc_acct_type):
        """Use an existing service account.

        Args:
            svc_acct_type (str): The service account type.

        Returns:
            str: The user specified service account.
        """
        existing_svc_acct = None
        while True:
            existing_svc_acct = raw_input(
                'Enter the full email of the service account '
                'you want to use or press [enter] to cancel: ').strip().lower()

            if not existing_svc_acct:
                return None

            if svc_acct_type == 'gsuite_service_account' and \
               existing_svc_acct == self.gcp_service_account:
                print('You are already using this service account for GCP. '
                      'Please choose another, or press [enter] to cancel.')
                continue

            proc = subprocess.Popen(
                ['gcloud', 'iam', 'service-accounts', 'describe',
                 existing_svc_acct],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE)
            _, err = proc.communicate()
            if proc.returncode:
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
            if proc.returncode:
                print(err)
            else:
                break
        full_svc_acct = self.SERVICE_ACCT_FMT.format(
            new_svc_acct, self.project_id)

        print('\nCreated new service account: %s\n' % full_svc_acct)
        return full_svc_acct

    def _download_gsuite_svc_acct_key(self):
        """Download the service account key."""
        print('Downloading GSuite service account key for %s'
              % self.gsuite_service_account)
        proc = subprocess.Popen(
            ['gcloud', 'iam', 'service-accounts', 'keys',
             'create', 'gsuite_key.json',
             '--iam-account=%s' % self.gsuite_service_account],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE)
        _, err = proc.communicate()
        if proc.returncode:
            print(err)

        self.gsuite_svc_acct_key_location = os.path.abspath(
            os.path.join(
                os.path.dirname(__file__),
                'gsuite_key.json'))

    def _set_service_account(self, which_svc_acct, svc_acct):
        """Set the service account.

        Args:
            which_svc_acct (str): Which service account (GCP/GSuite) to set.
            svc_acct (str): The service account full name.
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
            if proc.returncode:
                print(err)
                self.unassigned_roles.append(role)
            else:
                print('Done.')

    def setup_bucket_name(self):
        """Ask user to come up with a bucket name for the rules."""
        self._print_banner('Setup bucket name')
        default_bucket = self.DEFAULT_BUCKET_FORMAT.format(self.project_id)

        while True:
            bucket_name = raw_input(
                'Enter a bucket name (press [enter] to use '
                'the default: {}): '.format(default_bucket)).strip().lower()
            if not bucket_name:
                bucket_name = default_bucket

            if not bucket_name.startswith('gs://'):
                bucket_name = 'gs://{}'.format(bucket_name)

            if bucket_name:
                self.rules_bucket_name = bucket_name
                break

        print('Choose a region in which to create your bucket:')
        self.bucket_region = self._choose_region(self.BUCKET_REGIONS)

    def _choose_region(self, regions):
        """Choose which region to create data storage.

        Args:
            regions (list): List of regions.

        Returns:
            str: The region in which to create the data storage.
        """
        while True:
            prev_region = None
            for (i, region) in enumerate(regions):
                if region['region'] != prev_region:
                    print('\nRegion: %s' % region['region'])
                    print('--------------------------------')
                prev_region = region['region']
                print('[%s] %s' % (i+1, region['desc']))
            input_choice = raw_input(
                'Enter the number of your choice: ').strip()
            try:
                choice = int(input_choice)
                if choice < 1 or choice > len(regions):
                    raise ValueError('Invalid input choice')
                else:
                    return regions[choice-1]['value']
            except (TypeError, ValueError):
                print('Invalid choice, try again')

    def create_bucket(self):
        """Create the bucket."""
        print('\nCreating bucket...')
        proc = subprocess.Popen(
            ['gsutil', 'mb', '-l', self.bucket_region, self.rules_bucket_name],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE)
        _, err = proc.communicate()
        if proc.returncode:
            print(err)
        else:
            print('Done.\n')

    def setup_cloudsql_name(self):
        """Ask user to name their Cloud SQL instance."""
        self._print_banner('Setup Cloud SQL name')
        instance_name = raw_input(
            'Enter a name for the Forseti Cloud SQL instance '
            '(press [enter] to use the default: {}) '.format(
                self.DEFAULT_CLOUDSQL_INSTANCE_NAME))\
            .strip().lower()
        if not instance_name:
            instance_name = self.DEFAULT_CLOUDSQL_INSTANCE_NAME
        timestamp = datetime.datetime.now().strftime('%y%m%d%H%M')
        self.cloudsql_instance = '{}-{}'.format(instance_name, timestamp)

        print('\nChoose the region in which to host your Cloud SQL:')
        self.cloudsql_region = self._choose_region(self.CLOUDSQL_REGIONS)

    def setup_cloudsql_user(self):
        """Ask user to input Cloud SQL user name."""
        sql_user = raw_input(
            'Enter the sql user name of your choice '
            '(press [enter] to use the default: {}) '
            .format(self.DEFAULT_CLOUDSQL_USER)).strip().lower()
        if not sql_user:
            sql_user = self.DEFAULT_CLOUDSQL_USER
        self.cloudsql_user = sql_user

    def create_cloudsql_instance(self):
        """Create Cloud SQL instance."""
        if self.cloudsql_instance:
            print('Creating Cloud SQL instance... This will take awhile...')

            proc = subprocess.Popen(
                ['gcloud', 'sql', 'instances', 'create', self.cloudsql_instance,
                 '--region=%s' % self.cloudsql_region,
                 '--database-version=%s' % self.CLOUDSQL_DB_VERSION,
                 '--tier=%s' % self.CLOUDSQL_TIER,
                 '--storage-size=%s' % self.CLOUDSQL_STORAGE_SIZE_GB,
                 '--storage-type=%s' % self.CLOUDSQL_STORAGE_TYPE],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE)
            _, err = proc.communicate()
            if proc.returncode:
                print(err)

        if self.cloudsql_instance:
            proc = subprocess.Popen(
                ['gcloud', 'sql', 'users', 'create',
                 self.cloudsql_user, 'localhost',
                 '--instance', self.cloudsql_instance],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE)
            _, err = proc.communicate()
            if proc.returncode:
                print(err)
            else:
                print('Done.\n')

    def generate_deployment_templates(self):
        """Generate deployment templates."""
        self._print_banner('Generate Deployment Manager templates')

        deploy_tpl_path = os.path.abspath(
            os.path.join(
                self.ROOT_DIR_PATH,
                'deployment-templates',
                'deploy-forseti.yaml.in'))
        out_tpl_path = os.path.abspath(
            os.path.join(
                self.ROOT_DIR_PATH,
                'deployment-templates',
                'deploy-forseti-{}.yaml'.format(os.getpid())))
        rules_dir = os.path.abspath(
            os.path.join(
                self.ROOT_DIR_PATH, 'rules'))
        forseti_conf = os.path.abspath(
            os.path.join(
                self.ROOT_DIR_PATH, 'configs', 'forseti_conf.yaml'))

        # Determine which branch or release of Forseti to deploy
        if self.version:
            branch_or_release = self.BRANCH_RELEASE_FMT.format(
                'release-version', self.version)
        else:
            if not self.branch:
                self.branch = 'master'
            branch_or_release = self.BRANCH_RELEASE_FMT.format(
                'branch-name', self.branch)

        deploy_values = {
            'CLOUDSQL_REGION': self.cloudsql_region,
            'CLOUDSQL_INSTANCE_NAME': self.cloudsql_instance,
            'SCANNER_BUCKET': self.rules_bucket_name[len('gs://'):],
            'BUCKET_REGION': self.bucket_region,
            'GCP_SERVICE_ACCOUNT': self.gcp_service_account,
            'BRANCH_OR_RELEASE': branch_or_release,
        }

        with open(deploy_tpl_path, 'r') as in_tmpl:
            tmpl_contents = in_tmpl.read()
            out_contents = tmpl_contents.format(**deploy_values)
            with open(out_tpl_path, 'w') as out_tmpl:
                out_tmpl.write(out_contents)
                self.deploy_tpl_path = out_tpl_path

        print('\nCreated a deployment template:\n    %s\n' %
              self.deploy_tpl_path)

        deploy_choice = raw_input('Create a GCP deployment? '
                                  '(y/N) ').strip().lower()
        if deploy_choice == 'y':
            self.created_deployment = True
            _ = subprocess.call(
                ['gcloud', 'deployment-manager', 'deployments', 'create',
                 'forseti-security-{}'.format(os.getpid()),
                 '--config={}'.format(self.deploy_tpl_path)])
            time.sleep(2)
            _ = subprocess.call(
                ['gsutil', 'cp', forseti_conf,
                 '{}/configs/forseti_conf.yaml'.format(self.rules_bucket_name)])
            _ = subprocess.call(
                ['gsutil', 'cp', '-r', rules_dir,
                 '{}'.format(self.rules_bucket_name)])

    def create_data_storage(self):
        """Create Cloud SQL instance and Cloud Storage bucket. (optional)"""
        self._print_banner('Create data storage (optional)')
        print('Be advised! Only do these next 2 steps if you plan to deploy '
              'locally OR without Deployment Manager!\n')
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
        """
        self._print_banner('Post-setup instructions')

        print('Congratulations! You\'ve completed the Forseti prerequisite '
              'setup.\n')

        if self.gsuite_service_account:
            print('It looks like you created a service account for retrieving '
                  'GSuite groups.\n'
                  'There are just a few more steps to enable the groups '
                  'retrieval.\n\n')

            instructions = []
            instructions.append(
                '{}) Enable Domain Wide Delegation on %s.\n'
                'Please go to the following link:\n\n'
                '    https://console.cloud.google.com/iam-admin'
                '/serviceaccounts/project?project=%s&organizationId=%s\n\n'
                '  a) Look for the service account with ID "%s".\n'
                '  b) Click the dot menu on the right to see some options.\n'
                '  c) Click "Edit".\n'
                '  d) Check the box to "Enable domain-wide-delegation".\n'
                '  e) Click "Save".\n\n'
                %
                (self.project_id,
                 self.organization_id,
                 self.gsuite_service_account,
                 self.gsuite_service_account))

            if not self.gsuite_svc_acct_key_location:
                instructions.append(
                    '{}) Create and download the service account key.\n'
                    '  a) Click the dot menu again to see some options.\n'
                    '  b) Click "Create Key".\n'
                    '  c) Make sure the Key Type is "JSON".\n'
                    '  d) Click "Create". This downloads the key to your '
                    'computer.\n\n')

            instructions.append(
                '{}) Follow instructions on how to link the service account '
                'to GSuite:\n\n'
                '    '
                'http://forsetisecurity.org/docs/howto/gsuite-group-collection'
                '\n\n')

            if self.gsuite_svc_acct_key_location:
                instructions.append(
                    '{}) Your GSuite service account key has been '
                    'downloaded to:\n\n    %s\n\n'
                    'You will need the key when you run Forseti Inventory.\n'
                    % self.gsuite_svc_acct_key_location)

            for (i, instr_text) in enumerate(instructions):
                print(instr_text.format(i+1))

        if self.created_deployment:
            print('Since you chose to create a deployment via Deployment '
                  'Manager, you can check out the details in the Cloud '
                  'Console:\n\n'
                  '    https://console.cloud.google.com/deployments?'
                  'project={}\n\n'.format(self.project_id))
        else:
            print('Your generated Deployment Manager template can be '
                  'found here:\n\n    {}'.format(self.deploy_tpl_path))
            print('Please fill out your forseti_conf.yaml and rules files '
                  'if you have not already done so, then after creating your '
                  'deployment, copy the files from the root directory of '
                  'forseti-security, e.g.\n\n'
                  '    gsutil cp configs/forseti_conf.yaml '
                  '{}/configs/forseti_conf.yaml\n'
                  '    gsutil cp -r rules {}\n\n'.format(
                      self.rules_bucket_name,
                      self.rules_bucket_name))

        if self.unassigned_roles:
            print('Some required IAM roles could not be assigned. '
                  'Please ask your Organization Admin to run these commands '
                  'to assign the roles:\n\n')
            for role in self.unassigned_roles:
                print('gcloud organizations add-iam-policy-binding {} '
                      '--member=serviceAccount:{} --role={}\n'.format(
                          self.organization_id,
                          self.gcp_service_account,
                          role))
            print('\n\n')
