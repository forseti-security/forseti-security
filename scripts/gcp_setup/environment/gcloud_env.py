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
"""

from __future__ import print_function

import datetime
import json
import os
import subprocess
import sys
import time


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
    ]

    SERVICE_ACCT_FMT = '{}@{}.iam.gserviceaccount.com'

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
        'roles/cloudsql.client'
    ]

    DEFAULT_BUCKET_FORMAT = 'gs://{}-data'

    DEFAULT_CLOUDSQL_INSTANCE_NAME = 'forseti-security'
    CLOUDSQL_DB_VERSION = 'MYSQL_5_7'
    CLOUDSQL_TIER = 'db-n1-standard-1'
    CLOUDSQL_STORAGE_SIZE_GB = '25'
    CLOUDSQL_STORAGE_TYPE = 'SSD'

    ROOT_DIR_PATH = os.path.dirname(
        os.path.dirname(
            os.path.dirname(
                os.path.dirname(__file__))))

    def __init__(self, **kwargs):
        """Init.

        Args:
            kwargs (dict): The kwargs.
        """
        self.timestamp = datetime.datetime.now().strftime('%Y%m%d%H%M%S')
        self.force_no_cloudshell = kwargs.get('no_cloudshell')

        self.authed_user = None
        self.project_id = None
        self.organization_id = None

        self.gcp_service_account = None
        self.gsuite_service_account = None
        self.gsuite_svc_acct_key_location = None

        self.bucket_name = None
        self.bucket_region = kwargs.get('gcs_location')
        self.cloudsql_instance = '{}-{}'.format(
            self.DEFAULT_CLOUDSQL_INSTANCE_NAME,
            self.timestamp)
        self.cloudsql_region = kwargs.get('cloudsql_region')

        self.deployment_name = False
        self.deploy_tpl_path = None
        self.forseti_conf_path = None

        self.sendgrid_api_key = '""'
        self.notification_sender_email = '""'
        self.notification_recipient_email = '""'
        self.gcp_gsuite_key_path = '""'

    def run_setup(self):
        """Run the setup steps."""
        # Pre-flight checks.
        self.check_cloudshell()
        self.get_authed_user()
        self.get_project()
        self.get_organization()
        self.has_permissions()

        # Generate names and config.
        self.enable_apis()
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
        if return_code:
            self.copy_config_to_bucket()
            self.grant_gcp_svc_acct_roles()
            #self.copy_gsuite_key()

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

    def check_cloudshell(self):
        """Check if running in Cloud Shell."""
        self._print_banner('Check if using Cloud Shell')
        if not self.force_no_cloudshell:
            print('Forseti highly recommends running this wizard within '
                  'Cloud Shell. If you would like to run the wizard outside '
                  'Cloud Shell, please be sure to do the following:\n\n'
                  '1) Create a project.\n'
                  '2) Enable billing for the project.\n'
                  '3) Install gcloud and authenticate your account using '
                  '"gcloud auth login"\n.'
                  '4) Run this setup again, with the --no-cloudshell flag, '
                  'i.e.\n\n    python setup_forseti.py --no-cloudshell')
            sys.exit(1)
        else:
            print('Using Cloud Shell, continuing...')

    def get_authed_user(self):
        """Get the current authed user."""
        return_code, out, err = self._run_command(
            ['gcloud', 'auth', 'list', '--format=json'])

        if return_code:
            print(err)
        else:
            try:
                users = json.loads(out)
                active_users = [u.get('account')
                                for u in users if u.get('status') == 'ACTIVE']
                if active_users:
                    self.authed_user = active_users[0]
            except ValueError as verr:
                print(verr)

        if not self.authed_user:
            self._no_authed_user()

    @staticmethod
    def _no_authed_user():
        """No authed user, therefore exit."""
        print('Error getting authed user. You may need to run '
              '"gcloud auth login". Exiting.')
        sys.exit(1)

    def get_project(self):
        """Get the project."""
        return_code, out, err = self._run_command(
            ['gcloud', 'config', 'get-value', 'project'])
        if return_code or not out:
            print(err)
            print('You need to have an active project! Exiting.')
            sys.exit(1)
        self.project_id = out.strip()
        self._print_banner('Project id: %s' % self.project_id)

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
        parent_type = 'folder'
        while parent_type != 'organizations':
            return_code, out, err = self._run_command(
                ['gcloud', 'alpha', 'resource-manager', 'folders',
                 'describe', folder_id, '--format=json'])
            if return_code:
                print(err)
                self._no_organization()
            try:
                folder = json.loads(out)
                parent_type, parent_id = folder['parent'].split('/')
            except ValueError as verr:
                print(verr)
                self._no_organization()
        self.organization_id = parent_id

    def has_permissions(self):
        """Check if current user is an org admin and project owner.

        User must be an org admin in order to assign a service account roles
        on the organization IAM policy.
        """
        self._print_banner('Check if current user has necessary permissions')

        if self._is_org_admin() and self._can_modify_project_iam():
            print('You have the necessary roles to grant roles that Forseti '
                  'needs. Continuing...')
        else:
            print('You do not have the necessary roles to grant roles that '
                  'Forseti needs. Please have someone who is an Org Admin '
                  'and either Project Editor or Project Owner for this project '
                  'to run this setup wizard. Exiting.')
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
        """Check if user has certain roles in a resource.

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
                    if member.find(self.authed_user):
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
        for api in self.REQUIRED_APIS:
            print('Enabling the {} API...'.format(api['name']))
            return_code, _, err = self._run_command(
                ['gcloud', 'alpha', 'service-management',
                 'enable', api['service']])
            if return_code:
                print(err)
            else:
                print('Done.')

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
                os.getcwd(),
                'gsuite_key.json'))

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
            'organizations': self.ORG_IAM_ROLES,
            'projects': self.PROJECT_IAM_ROLES
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
                    '--member=serviceAccount:%s' % self.gcp_service_account,
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
        self._print_banner('Generate bucket name')
        self.bucket_name = self.DEFAULT_BUCKET_FORMAT.format(self.project_id)
        print('Bucket name will be: %s' % self.bucket_name)

    def generate_deployment_templates(self):
        """Generate deployment templates."""
        self._print_banner('Generate Deployment Manager templates')

        # Deployment template in file
        deploy_tpl_path = os.path.abspath(
            os.path.join(
                self.ROOT_DIR_PATH,
                'deployment-templates',
                'deploy-forseti.yaml.in'))
        out_tpl_path = os.path.abspath(
            os.path.join(
                self.ROOT_DIR_PATH,
                'deployment-templates',
                'deploy-forseti-{}.yaml'.format(self.timestamp)))

        deploy_values = {
            'CLOUDSQL_REGION': self.cloudsql_region,
            'CLOUDSQL_INSTANCE_NAME': self.cloudsql_instance,
            'SCANNER_BUCKET': self.bucket_name[len('gs://'):],
            'BUCKET_REGION': self.bucket_region,
            'GCP_SERVICE_ACCOUNT': self.gcp_service_account,
            'BRANCH_OR_RELEASE': 'master',
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
        forseti_conf_in = os.path.abspath(
            os.path.join(
                self.ROOT_DIR_PATH, 'configs', 'forseti_conf.yaml.in'))
        forseti_conf_gen = os.path.abspath(
            os.path.join(
                self.ROOT_DIR_PATH, 'configs', 'forseti_conf_dm.yaml'))

        # Ask for SendGrid API Key
        sendgrid_api_key = raw_input(
            'What is your SendGrid API key? (press [enter] to '
            'leave blank) ').strip()
        if sendgrid_api_key:
            self.sendgrid_api_key = sendgrid_api_key

            # Ask for notification sender email
            self.notification_sender_email = 'forseti-notify@localhost.domain'

            # Ask for notification recipient email
            notification_recipient_email = raw_input(
                'At what email address do you want to receive notifications? '
                '(press [enter] to leave blank) ').strip()
            if notification_recipient_email:
                self.notification_recipient_email = notification_recipient_email

        conf_values = {
            'EMAIL_RECIPIENT': self.notification_recipient_email,
            'EMAIL_SENDER': self.notification_sender_email,
            'SENDGRID_API_KEY': self.sendgrid_api_key,
            'SCANNER_BUCKET': self.bucket_name[len('gs://'):],
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
        self.deployment_name = 'forseti-security-{}'.format(os.getpid())
        print('Deployment name: %s' % self.deployment_name)
        return_code, out, err = self._run_command(
            ['gcloud', 'deployment-manager', 'deployments', 'create',
             self.deployment_name, '--config={}'.format(self.deploy_tpl_path)])
        time.sleep(2)
        if return_code:
            print(err)
        else:
            print(out)

        return return_code

    def copy_config_to_bucket(self):
        """Copy the config to the created bucket.

        Returns:
            bool: True if copy config succeeded, otherwise False.
            bool: True if copy rules succeeded, otherwise False.
        """
        copy_config_ok = False
        copy_rules_ok = False

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
                self.ROOT_DIR_PATH, 'rules'))
        return_code, out, err = self._run_command(
            ['gsutil', 'cp', '-r', rules_dir, self.bucket_name])
        if return_code:
            print(err)
        else:
            print(out)
            copy_rules_ok = True

        return copy_config_ok, copy_rules_ok

    def post_install_instructions(self):
        """Show post-install instructions.

        Print link to go to GSuite service account and enable DWD.

        Print link for deployment manager dashboard.
        """
        self._print_banner('Post-setup instructions')

        if self.gsuite_service_account:
            print('Here are your next steps:\n')
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
                 self.project_id,
                 self.organization_id,
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

        if self.deployment_name:
            print('You can check out the details of your deployment in the '
                  'Cloud Console:\n\n'
                  '    https://console.cloud.google.com/deployments?'
                  'project={}\n\n'.format(self.project_id))

            if self.gsuite_service_account:
                print('Since you are using a GSuite service account, after you '
                      'download the json key, copy it to your Forseti instance '
                      'with the following command:\n\n'
                      '    gcloud compute scp <keyfile name> '
                      'ubuntu@{}-vm:/home/ubuntu/gsuite_key.json\n\n'.format(
                          self.deployment_name))
        else:
            print('Your generated Deployment Manager template can be '
                  'found here:\n\n    {}\n'.format(self.deploy_tpl_path))
            print('A forseti_conf_dm.yaml file has been generated. '
                  'After creating your deployment, copy the following files '
                  'from the root directory of forseti-security to '
                  'your Forseti bucket:\n\n'
                  '    gsutil cp configs/forseti_conf_dm.yaml '
                  '{}/configs/forseti_conf.yaml\n'
                  '    gsutil cp -r rules {}\n\n'.format(
                      self.bucket_name,
                      self.bucket_name))
