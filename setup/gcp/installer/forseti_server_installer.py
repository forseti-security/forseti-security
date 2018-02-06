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

"""Forseti Server installer"""

from __future__ import print_function
import random

from forseti_installer import ForsetiInstaller
from util.utils import (
    print_banner, format_resource_id, format_service_acct_id)
from util.constants import (
    MESSAGE_ENABLE_GSUITE_GROUP, MESSAGE_SETUP_IAM_EXPLAIN,
    QUESTION_ENABLE_IAM_EXPLAIN, QUESTION_ACCESS_TO_GRANT_ROLES,
    RESOURCE_TYPES, MESSAGE_FORSETI_CONFIGURATION_ACCESS_LEVEL,
    QUESTION_FORSETI_CONFIGURATION_ACCESS_LEVEL, MESSAGE_ASK_SENDGRID_API_KEY,
    QUESTION_SENDGRID_API_KEY, NOTIFICATION_SENDER_EMAIL, MESSAGE_SKIP_EMAIL,
    QUESTION_NOTIFICATION_RECIPIENT_EMAIL, QUESTION_GSUITE_SUPERADMIN_EMAIL,
    MESSAGE_ASK_GSUITE_SUPERADMIN_EMAIL, QUESTION_ENABLE_WRITE_ACCESS,
    MESSAGE_HAS_ROLE_SCRIPT, MESSAGE_GSUITE_DATA_COLLECTION)
from util.gcloud import (
    enable_apis, create_reuse_service_acct, choose_organization,
    choose_folder, choose_project, grant_server_svc_acct_roles)
from configs.server_config import ServerConfig


class ForsetiServerInstaller(ForsetiInstaller):
    """Forseti server installer"""

    # pylint: disable=too-many-instance-attributes
    # Having ten variables is reasonable in this case.

    gsuite_service_account = None
    has_roles_script = False
    setup_explain = True
    enable_write_access = False
    resource_root_id = None
    access_target = None
    target_id = None

    def __init__(self, **kwargs):
        """Init

        Args:
            kwargs (dict): The kwargs.
        """
        super(ForsetiServerInstaller, self).__init__()
        self.config = ServerConfig(**kwargs)

    def preflight_checks(self):
        """Pre-flight checks for server instance"""

        super(ForsetiServerInstaller, self).preflight_checks()

        self.should_setup_explain()
        self.determine_access_target()
        self.should_enable_write_access()
        self.format_gsuite_service_acct_id()
        self.inform_access_on_target()

        enable_apis(self.config.dry_run)
        self.gsuite_service_account = create_reuse_service_acct(
            'gsuite_service_account',
            self.gsuite_service_account,
            self.config.advanced_mode,
            self.config.dry_run)
        self.get_email_settings()

    def deploy(self, deploy_tpl_path, conf_file_path, bucket_name):
        """Deploy Forseti using the deployment template.
        Grant access to service account.

        Args:
            deploy_tpl_path (str): Deployment template path
            conf_file_path (str): Configuration file path
            bucket_name (str): Name of the GCS bucket

        Returns:
            bool: Whether or not the deployment was successful
            str: Deployment name
        """
        success, deployment_name = super(ForsetiServerInstaller, self).deploy(
            deploy_tpl_path, conf_file_path, bucket_name)

        if success:
            self.has_roles_script = grant_server_svc_acct_roles(
                self.enable_write_access,
                self.access_target,
                self.target_id,
                self.project_id,
                self.gsuite_service_account,
                self.gcp_service_account,
                self.user_can_grant_roles)

        return success, deployment_name

    def should_setup_explain(self):
        """Ask user if they want to configure setup for Explain."""
        print_banner('Enable IAM Explain')
        print(MESSAGE_SETUP_IAM_EXPLAIN)
        choice = None
        if not self.config.advanced_mode:
            choice = 'y'
            print('Automatically enabling IAM Explain (basic setup mode).')

        while not choice:
            choice = raw_input(QUESTION_ENABLE_IAM_EXPLAIN).strip()
        self.setup_explain = choice == 'y'

    def inform_access_on_target(self):
        """Inform user that they need IAM access to grant Forseti access."""
        print_banner('Current IAM access')
        choice = None

        if not self.config.advanced_mode:
            choice = 'y'

        while choice != 'y' and choice != 'n':
            choice = raw_input(QUESTION_ACCESS_TO_GRANT_ROLES.format(
                self.resource_root_id)).strip().lower()

        if choice == 'y':
            self.user_can_grant_roles = True
            print('Will attempt to grant roles on the target %s.' %
                  self.resource_root_id)
        else:
            self.user_can_grant_roles = False
            print('Will NOT attempt to grant roles on the target %s.' %
                  self.resource_root_id)

    def get_deployment_values(self):
        """Get deployment values

        Returns:
            dict: A dictionary of values needed to generate
                the forseti deployment template
        """
        return {
            'CLOUDSQL_REGION': self.config.cloudsql_region,
            'CLOUDSQL_INSTANCE_NAME': self.config.cloudsql_instance,
            'SCANNER_BUCKET': self.generate_bucket_name()[len('gs://'):],
            'BUCKET_LOCATION': self.config.bucket_location,
            'SERVICE_ACCOUNT_GCP': self.gcp_service_account,
            'SERVICE_ACCOUNT_GSUITE': self.gsuite_service_account,
            'BRANCH_OR_RELEASE': 'branch-name: "{}"'.format(self.branch),
            'GSUITE_ADMIN_EMAIL': self.config.gsuite_superadmin_email,
            'ROOT_RESOURCE_ID': self.resource_root_id,
            'rand_minute': random.randint(0, 59)
        }

    def get_configuration_values(self):
        """Get configuration values

        Returns:
            dict: A dictionary of values needed to generate
                the forseti configuration file
        """
        return {
            'EMAIL_RECIPIENT': self.config.notification_recipient_email,
            'EMAIL_SENDER': self.config.notification_sender_email,
            'SENDGRID_API_KEY': self.config.sendgrid_api_key,
            'SCANNER_BUCKET': self.generate_bucket_name()[len('gs://'):],
            'DOMAIN_SUPER_ADMIN_EMAIL': self.config.gsuite_superadmin_email,
            'ENABLE_GROUP_SCANNER': 'true',
        }

    def determine_access_target(self):
        """Determine where to enable Forseti access.

        Either org, folder, or project level.
        """
        print_banner('Forseti access target')

        if not self.config.advanced_mode:
            self.access_target = RESOURCE_TYPES[0]
            self.target_id = self.organization_id

        while not self.target_id:
            if self.setup_explain:
                # If user wants to setup Explain, they must setup
                # access on an organization.
                choice_index = 1
            else:
                try:
                    print(MESSAGE_FORSETI_CONFIGURATION_ACCESS_LEVEL)
                    for (i, choice) in enumerate(RESOURCE_TYPES):
                        print('[%s] %s' % (i+1, choice))
                    choice_input = raw_input(
                        QUESTION_FORSETI_CONFIGURATION_ACCESS_LEVEL).strip()
                    choice_index = int(choice_input)
                except ValueError:
                    print('Invalid choice, try again.')
                    continue

            if choice_index and choice_index <= len(RESOURCE_TYPES):
                self.access_target = RESOURCE_TYPES[choice_index-1]
                if self.access_target == 'organization':
                    self.target_id = choose_organization()
                elif self.access_target == 'folder':
                    self.target_id = choose_folder(self.organization_id)
                else:
                    self.target_id = choose_project()

        self.resource_root_id = format_resource_id(
            '%ss' % self.access_target, self.target_id)

        print('Forseti will be granted access to: %s' %
              self.resource_root_id)

    def get_email_settings(self):
        """Ask user for specific setup values."""
        if not self.config.sendgrid_api_key:
            # Ask for SendGrid API Key
            print(MESSAGE_ASK_SENDGRID_API_KEY)
            self.config.sendgrid_api_key = raw_input(
                QUESTION_SENDGRID_API_KEY).strip()
        if self.config.sendgrid_api_key:
            self.config.notification_sender_email = NOTIFICATION_SENDER_EMAIL

            # Ask for notification recipient email
            if not self.config.notification_recipient_email:
                self.config.notification_recipient_email = raw_input(
                    QUESTION_NOTIFICATION_RECIPIENT_EMAIL).strip()

        if not self.config.gsuite_superadmin_email:
            # Ask for G Suite super admin email
            print(MESSAGE_ASK_GSUITE_SUPERADMIN_EMAIL)
            self.config.gsuite_superadmin_email = raw_input(
                QUESTION_GSUITE_SUPERADMIN_EMAIL).strip()

    def format_gsuite_service_acct_id(self):
        """Format the gsuite service account id"""
        self.gsuite_service_account = format_service_acct_id(
            'gsuite',
            'reader',
            self.config.timestamp,
            self.project_id)

    def format_gcp_service_acct_id(self):
        """Format the service account ids."""
        modifier = 'reader'
        if self.enable_write_access:
            modifier = 'readwrite'

        self.gcp_service_account = format_service_acct_id(
            'gcp',
            modifier,
            self.config.timestamp,
            self.project_id)

    def should_enable_write_access(self):
        """Ask if user wants to enable write access for Forseti."""
        print_banner('Enable Forseti write access')
        choice = None
        if not self.config.advanced_mode:
            choice = 'y'

        while choice != 'y' and choice != 'n':
            choice = raw_input(QUESTION_ENABLE_WRITE_ACCESS).strip().lower()

        if choice == 'y':
            self.enable_write_access = True
            print('Forseti will have write access on %s.' %
                  self.resource_root_id)

    def post_install_instructions(self, deploy_success, deployment_name,
                                  deploy_tpl_path, forseti_conf_path,
                                  bucket_name):

        super(ForsetiServerInstaller, self) \
            .post_install_instructions(deploy_success, deployment_name,
                                       deploy_tpl_path, forseti_conf_path,
                                       bucket_name)
        if self.has_roles_script:
            print(MESSAGE_HAS_ROLE_SCRIPT.format(self.resource_root_id))

        if not self.config.sendgrid_api_key:
            print(MESSAGE_SKIP_EMAIL)

        if self.config.gsuite_superadmin_email:
            print(MESSAGE_GSUITE_DATA_COLLECTION.format(
                self.project_id,
                self.organization_id,
                self.gsuite_service_account))
        else:
            print(MESSAGE_ENABLE_GSUITE_GROUP)
