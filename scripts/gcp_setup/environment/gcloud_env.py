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

from __future__ import print_function

import datetime
import json
import os
import re
import subprocess
import sys
import time


DEFAULT_BUCKET_FMT = 'gs://{}-data-{}'
DEFAULT_CLOUDSQL_INSTANCE_NAME = 'forseti-security'

GCLOUD_MIN_VERSION = (163, 0, 0)
GCLOUD_VERSION_REGEX = r'Google Cloud SDK (.*)'
GCLOUD_ALPHA_REGEX = r'alpha.*'

GSUITE_KEY_SCP_ATTEMPTS = 5
GSUITE_KEY_NAME = 'gsuite_key.json'

ORG_IAM_ROLES = [
    'roles/browser',
    'roles/compute.networkViewer',
    'roles/iam.securityReviewer',
    'roles/appengine.appViewer',
    'roles/servicemanagement.quotaViewer',
    'roles/cloudsql.viewer',
    'roles/compute.securityAdmin',
]

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

SERVICE_ACCT_FMT = 'forseti-{}-reader-{}'
SERVICE_ACCT_EMAIL_FMT = '{}@{}.iam.gserviceaccount.com'

ROOT_DIR_PATH = os.path.dirname(
    os.path.dirname(
        os.path.dirname(
            os.path.dirname(__file__))))


def org_id_from_org_name(org_name):
    """Extract the organization id (number) from the organization name.

    Args:
        org_name (str): The name of the organization, formatted as
            "organizations/${ORGANIZATION_ID}".

    Returns:
        str: just the organization_id.
    """
    return org_name[len('organizations/'):]


# pylint: disable=no-self-use
# pylint: disable=too-many-instance-attributes
class ForsetiGcpSetup(object):
    """Setup the Forseti Security GCP components."""

    def __init__(self, **kwargs):
        """Init.

        Args:
            kwargs (dict): The kwargs.
        """
        self.timestamp = datetime.datetime.now().strftime('%Y%m%d%H%M%S')
        self.timeonly = self.timestamp[8:]
        self.force_no_cloudshell = kwargs.get('no_cloudshell')
        self.branch = kwargs.get('branch') or 'master'

        self.is_devshell = False
        self.authed_user = None
        self.project_id = None
        self.organization_id = None

        self.gcp_service_account = SERVICE_ACCT_FMT.format(
            'gcp', self.timeonly)
        self.gsuite_service_account = SERVICE_ACCT_FMT.format(
            'gsuite', self.timeonly)
        self.gsuite_svc_acct_key_location = None

        self.bucket_name = None
        self.bucket_location = kwargs.get('gcs_location') or 'us-central1'
        self.cloudsql_instance = '{}-{}'.format(
            DEFAULT_CLOUDSQL_INSTANCE_NAME,
            self.timestamp)
        self.cloudsql_region = kwargs.get('cloudsql_region') or 'us-central1'
        self.gce_zone = '{}-c'.format(self.cloudsql_region)

        self.deployment_name = False
        self.deploy_tpl_path = None
        self.forseti_conf_path = None

        self.skip_email = False
        self.sendgrid_api_key = '""'
        self.notification_sender_email = '""'
        self.notification_recipient_email = '""'

    def run_setup(self):
        """Run the setup steps."""
        # Pre-flight checks.
        self._print_banner('Pre-flight checks')
        self.gcloud_info()
        self.check_cloudshell()
        self.get_authed_user()
        self.get_project()
        self.get_organization()
        self.has_permissions()

        self.enable_apis()

        # Generate names and config.
        self._print_banner('Generate configs')
        self.generate_bucket_name()
        self.generate_deployment_templates()
        self.generate_forseti_conf()

        # Actual deployment.
        # 1. Create deployment.
        # 2. If fails, continue to next step.
        # 3. Otherwise, copy configs (forseti_conf.yaml, rules) to bucket.
        # 4. Grant service account roles and create and download
        #    G Suite service account key.
        # 5. Poll the Forseti VM until it responds, then scp the key.
        return_code = self.create_deployment()
        if not return_code:
            self.copy_config_to_bucket()
            self.grant_gcp_svc_acct_roles()
            self.download_gsuite_svc_acct_key()
            self.copy_gsuite_key()

        self.post_install_instructions(deploy_success=(not return_code))

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

    @staticmethod
    def _run_command(cmd_args):
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

    def check_proper_gcloud(self):
        """Check gcloud version and presence of alpha components."""
        return_code, out, err = self._run_command(
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

        print('Current gcloud version: {}'.format(version))
        print('Has alpha components? {}'.format(alpha_match is not None))
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

    def gcloud_info(self):
        """Read gcloud info, and check if running in Cloud Shell."""
        # Read gcloud info
        return_code, out, err = self._run_command(
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
                print('Got gcloud info')
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

    def get_authed_user(self):
        """Get the current authed user."""
        if not self.authed_user:
            print('Error getting authed user. You may need to run '
                  '"gcloud auth login". Exiting.')
            sys.exit(1)
        print('You are: {}'.format(self.authed_user))

    def get_project(self):
        """Get the project."""
        if not self.project_id:
            print('You need to have an active project! Exiting.')
            sys.exit(1)
        print('Project id: %s' % self.project_id)

    def get_organization(self):
        """Infer the organization from the project's parent."""
        return_code, out, err = self._run_command(
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

    def _no_organization(self):
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
            return_code, out, err = self._run_command(
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

    def has_permissions(self):
        """Check if current user is an org admin and project owner.

        User must be an org admin in order to assign a service account roles
        on the organization IAM policy.
        """
        self._print_banner('Checking permissions')

        if self._is_org_admin() and self._can_modify_project_iam():
            print('You have the necessary roles to grant roles that Forseti '
                  'needs. Continuing...')
        else:
            print('You do not have the necessary roles to grant roles that '
                  'Forseti needs. Please have someone who is an Org Admin '
                  'and either Project Editor or Project Owner for this project '
                  'to run this setup. Exiting.')
            sys.exit(1)

    def _is_org_admin(self):
        """Check if current user is an org admin.

        Returns:
            bool: Whether current user is Org Admin.
        """
        is_org_admin = self._has_roles(
            'organizations',
            self.organization_id,
            ['roles/resourcemanager.organizationAdmin'])

        print('%s is Org Admin? %s' % (self.authed_user, is_org_admin))
        return is_org_admin

    def _can_modify_project_iam(self):
        """Check whether user can modify the current project's IAM policy.

        To make it simple, check that user is either Project Editor or Owner.

        Returns:
            bool: If user can modify a project.
        """
        can_modify_project = self._has_roles(
            'projects',
            self.project_id,
            ['roles/editor', 'roles/owner'])

        print('%s is either Project Editor or Owner? %s' %
              (self.authed_user, can_modify_project))
        return can_modify_project

    def _has_roles(self, resource_type, resource_id, roles):
        """Check if user has one or more roles in a resource.

        Args:
            resource_type (str): The resource type.
            resource_id (str): The resource id.
            roles (list): The roles to check user's membership in.

        Returns:
            bool: True if has roles, otherwise False.
        """
        has_roles = False
        return_code, out, err = self._run_command(
            ['gcloud', resource_type, 'get-iam-policy',
             resource_id, '--format=json'])
        if return_code:
            print(err)
        else:
            try:
                # Search resource's policy bindings for:
                # 1) Members who have certain roles.
                # 2) Whether the current authed user is in the members list.
                iam_policy = json.loads(out)
                role_members = []
                for binding in iam_policy.get('bindings', []):
                    if binding['role'] in roles:
                        role_members.extend(binding['members'])

                for member in role_members:
                    if member.find(self.authed_user) > -1:
                        has_roles = True
                        break
            except ValueError as verr:
                print(verr)
                print('Error reading output of %s.getIamPolicy().' %
                      resource_type)

        return has_roles

    def enable_apis(self):
        """Enable necessary APIs for Forseti Security.

        Technically, this could be done in Deployment Manager, but if you
        delete the deployment, you'll disable the APIs. This could cause errors
        if there are resources still in use (e.g. Compute Engine), and then
        your deployment won't be cleanly deleted.
        """
        self._print_banner('Enabling required APIs')
        for api in REQUIRED_APIS:
            print('Enabling the {} API...'.format(api['name']))
            return_code, _, err = self._run_command(
                ['gcloud', 'alpha', 'service-management',
                 'enable', api['service']])
            if return_code:
                print(err)
            else:
                print('Done.')

    def _full_service_acct_email(self, account_id):
        """Generate the full service account email.

        Args:
            account_id (str): The service account id, i.e. the part before
                the "@".

        Returns:
            str: The full service account email.
        """
        return SERVICE_ACCT_EMAIL_FMT.format(account_id, self.project_id)

    def download_gsuite_svc_acct_key(self):
        """Download the service account key."""
        print('\nDownloading GSuite service account key for %s'
              % self.gsuite_service_account)
        proc = subprocess.Popen(
            ['gcloud', 'iam', 'service-accounts', 'keys',
             'create', GSUITE_KEY_NAME,
             '--iam-account=%s' % (self._full_service_acct_email(
                 self.gsuite_service_account))],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE)
        _, err = proc.communicate()
        if proc.returncode:
            print(err)

        self.gsuite_svc_acct_key_location = os.path.abspath(
            os.path.join(
                os.getcwd(),
                GSUITE_KEY_NAME))

    def grant_gcp_svc_acct_roles(self):
        """Grant the following IAM roles to GCP service account.

        Org:
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
        self._print_banner('Assigning roles to the GCP service account')
        if not self.organization_id:
            self._no_organization()

        roles = {
            'organizations': ORG_IAM_ROLES,
            'projects': PROJECT_IAM_ROLES
        }

        for (resource_type, roles) in roles.iteritems():
            if resource_type == 'organizations':
                resource_id = self.organization_id
            else:
                resource_id = self.project_id

            for role in roles:
                iam_role_cmd = [
                    'gcloud',
                    resource_type,
                    'add-iam-policy-binding',
                    resource_id,
                    '--member=serviceAccount:%s' % (
                        self._full_service_acct_email(
                            self.gcp_service_account)),
                    '--role=%s' % role,
                ]
                print('Assigning %s on %s...' % (role, resource_id))
                proc = subprocess.Popen(iam_role_cmd,
                                        stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE)
                _, err = proc.communicate()
                if proc.returncode:
                    print(err)
                else:
                    print('Done.')

    def generate_bucket_name(self):
        """Generate bucket name for the rules."""
        self.bucket_name = DEFAULT_BUCKET_FMT.format(
            self.project_id, self.timeonly)

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
                'deploy-forseti-{}.yaml'.format(self.timestamp)))

        deploy_values = {
            'CLOUDSQL_REGION': self.cloudsql_region,
            'CLOUDSQL_INSTANCE_NAME': self.cloudsql_instance,
            'SCANNER_BUCKET': self.bucket_name[len('gs://'):],
            'BUCKET_LOCATION': self.bucket_location,
            'SERVICE_ACCT_GCP_READER': self.gcp_service_account,
            'SERVICE_ACCT_GSUITE_READER': self.gsuite_service_account,
            'BRANCH_OR_RELEASE': 'branch-name: "{}"'.format(self.branch),
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
        # Create a forseti_conf_dm.yaml config file with values filled in.
        # forseti_conf.yaml in file
        print('Generate forseti_conf_dm.yaml...\n')
        forseti_conf_in = os.path.abspath(
            os.path.join(
                ROOT_DIR_PATH, 'configs', 'forseti_conf.yaml.in'))
        forseti_conf_gen = os.path.abspath(
            os.path.join(
                ROOT_DIR_PATH, 'configs', 'forseti_conf_dm.yaml'))

        # Ask for SendGrid API Key
        print('Forseti can send email notifications through SendGrid '
              'via an API key. '
              'This step is optional and can be configured later.')
        sendgrid_api_key = raw_input(
            'What is your SendGrid API key? (press [enter] to skip) ').strip()
        if sendgrid_api_key:
            self.sendgrid_api_key = sendgrid_api_key

            # Ask for notification sender email
            self.notification_sender_email = 'forseti-notify@localhost.domain'

            # Ask for notification recipient email
            notification_recipient_email = raw_input(
                'At what email address do you want to receive notifications? '
                '(press [enter] to skip) ').strip()
            if notification_recipient_email:
                self.notification_recipient_email = notification_recipient_email
        else:
            self.skip_email = True

        conf_values = {
            'EMAIL_RECIPIENT': self.notification_recipient_email,
            'EMAIL_SENDER': self.notification_sender_email,
            'SENDGRID_API_KEY': self.sendgrid_api_key,
            'SCANNER_BUCKET': self.bucket_name[len('gs://'):],
            'GROUPS_SERVICE_ACCOUNT_KEY_FILE':
                '/home/ubuntu/{}'.format(GSUITE_KEY_NAME),
            'DOMAIN_SUPER_ADMIN_EMAIL': '""',
            'ENABLE_GROUP_SCANNER': 'true',
        }

        with open(forseti_conf_in, 'r') as in_tmpl:
            tmpl_contents = in_tmpl.read()
            out_contents = tmpl_contents.format(**conf_values)
            with open(forseti_conf_gen, 'w') as out_tmpl:
                out_tmpl.write(out_contents)
                self.forseti_conf_path = forseti_conf_gen

        print('\nCreated forseti_conf_dm.yaml config file:\n    %s\n' %
              self.forseti_conf_path)

    def create_deployment(self):
        """Create the GCP deployment.

        Returns:
            int: The return code value of running `gcloud` command to create
                the deployment.
        """
        self._print_banner('Create Forseti deployment')
        print ('This may take a few minutes.')
        self.deployment_name = 'forseti-security-{}'.format(self.timestamp)
        print('Deployment name: %s' % self.deployment_name)
        print('Deployment Manager Dashboard: '
              'https://console.cloud.google.com/deployments/details/'
              '{}?project={}&organizationId={}\n'.format(
                  self.deployment_name, self.project_id, self.organization_id))
        return_code, out, err = self._run_command(
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

        self._print_banner('Copy configs to bucket')

        print('Copy forseti_conf.yaml to {}'.format(self.bucket_name))
        return_code, out, err = self._run_command(
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
        return_code, out, err = self._run_command(
            ['gsutil', 'cp', '-r', rules_dir, self.bucket_name])
        if return_code:
            print(err)
        else:
            print(out)
            copy_rules_ok = True

        return copy_config_ok, copy_rules_ok

    def copy_gsuite_key(self):
        """scp the G Suite key to the VM after deployment.

        Use 2**<attempt #> seconds of sleep() between attempts.
        """
        self._print_banner('Copy G Suite key to Forseti VM')
        print('scp-ing your gsuite_key.json to your Forseti GCE instance...')
        for i in range(1, GSUITE_KEY_SCP_ATTEMPTS+1):
            print('Attempt {} of {} ...'.format(i, GSUITE_KEY_SCP_ATTEMPTS))
            return_code, out, err = self._run_command(
                ['gcloud',
                 'compute',
                 'scp',
                 '--zone={}'.format(self.gce_zone),
                 '--quiet',
                 self.gsuite_svc_acct_key_location,
                 'ubuntu@{}-vm:/home/ubuntu/{}'.format(
                     self.deployment_name, GSUITE_KEY_NAME),
                ])
            if return_code:
                print(err)
                if i+1 < GSUITE_KEY_SCP_ATTEMPTS:
                    sleep_time = 2**(i+1)
                    print('Trying again in %s seconds.' % (sleep_time))
                    time.sleep(sleep_time)
            else:
                print(out)
                print('Done')
                break

    def post_install_instructions(self, deploy_success):
        """Show post-install instructions.

        Print link for deployment manager dashboard.
        Print link to go to GSuite service account and enable DWD.

        Args:
            deploy_success (bool): Whether deployment was successful.
        """
        self._print_banner('Post-setup instructions')

        print('Your generated Deployment Manager template can be '
              'found here:\n\n    {}\n\n'.format(self.deploy_tpl_path))

        if not deploy_success:
            print ('Your deployment had some issues. Please review the error '
                   'messages. If you need help, please either file an issue '
                   'on our Github Issues or email '
                   'discuss@forsetisecurity.org.\n')

        print('You can see the details of your deployment in the '
              'Cloud Console:\n\n    '
              'https://console.cloud.google.com/deployments/details/'
              '{}?project={}&organizationId={}\n\n'.format(
                  self.deployment_name, self.project_id, self.organization_id))

        if self.skip_email:
            print('If you would like to enable email notifications via '
                  'SendGrid, please refer to:\n\n    '
                  'http://forsetisecurity.org/docs/howto/configure/'
                  'email-notification\n\n')

        print('Finalize your installation by enabling G Suite Groups '
              'collection in Forseti:\n\n'
              '    '
              'http://forsetisecurity.org/docs/howto/configure/'
              'gsuite-group-collection\n\n')
        
        print('A default configuration (configs/forseti_conf_dm.yaml) '
              'file has been generated. If wish to change your '
              'Forseti configuration or rules, e.g. after enabling '
              'GSuite Groups collection you copy the changed files '
              'from the root directory of forseti-security/ to '
              'your Forseti bucket:\n\n'
              '    gsutil cp configs/forseti_conf_dm.yaml '
              '{}/configs/forseti_conf.yaml\n\n'
              '    gsutil cp -r rules {}\n\n'.format(
                  self.bucket_name,
                  self.bucket_name))
