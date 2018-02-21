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

"""Forseti Server installer."""

from __future__ import print_function
import os
import random

from configs.server_config import ServerConfig
from forseti_installer import ForsetiInstaller
from util import constants
from util import files
from util import gcloud
from util import utils
from util import v1_upgrader


class ForsetiServerInstaller(ForsetiInstaller):
    """Forseti server installer"""

    # pylint: disable=too-many-instance-attributes

    gsuite_service_account = None
    has_roles_script = False
    setup_explain = True
    enable_write_access = False
    resource_root_id = None
    access_target = None
    target_id = None
    migrate_from_v1 = False

    def __init__(self, **kwargs):
        """Init

        Args:
            kwargs (dict): The kwargs.
        """
        super(ForsetiServerInstaller, self).__init__()
        self.config = ServerConfig(**kwargs)
        self.v1_config = None

    def preflight_checks(self):
        """Pre-flight checks for server instance"""

        super(ForsetiServerInstaller, self).preflight_checks()
        gcloud.enable_apis(self.config.dry_run)
        forseti_v1_name = None
        if not self.config.dry_run:
            _, zone, forseti_v1_name = gcloud.get_vm_instance_info(
                r'^forseti-security-\d+-vm$', try_match=True)
        if forseti_v1_name:
            utils.print_banner('Import configuration and rules from v1')
            # v1 instance exists, ask if the user wants to port
            # the conf/rules settings from v1.
            self.prompt_v1_configs_migration()
        if self.migrate_from_v1:
            self.v1_config = v1_upgrader.ForsetiV1Configuration(
                self.project_id, forseti_v1_name, zone)
            self.v1_config.fetch_information_from_gcs()
            self.populate_config_info_from_v1()
        self.determine_access_target()
        self.should_enable_write_access()
        self.format_gsuite_service_acct_id()
        self.should_grant_access()

        self.gsuite_service_account = gcloud.create_or_reuse_service_acct(
            'gsuite_service_account',
            self.gsuite_service_account,
            self.config.advanced_mode,
            self.config.dry_run)
        self.get_email_settings()

    def prompt_v1_configs_migration(self):
        """Ask the user if they want to migrate conf/rule files
        from v1 to v2."""
        while self.migrate_from_v1 != 'y' and self.migrate_from_v1 != 'n':
            self.migrate_from_v1 = raw_input(
                "Forseti v1 detected, would you like to migrate the "
                "existing configurations to v2? (y/n): ").lower()

    def populate_config_info_from_v1(self):
        """Retrieve the v1 configuration object."""
        v1_conf_global = self.v1_config.config.get('global')
        self.config.sendgrid_api_key = v1_conf_global.get('sendgrid_api_key')
        self.config.gsuite_superadmin_email = v1_conf_global.get(
            'domain_super_admin_email')
        self.config.notification_recipient_email = v1_conf_global.get(
            'email_recipient')
        self.config.notification_sender_email = v1_conf_global.get(
            'email_sender')

    def deploy(self, deployment_tpl_path, conf_file_path, bucket_name):
        """Deploy Forseti using the deployment template.
        Grant access to service account.

        Args:
            deployment_tpl_path (str): Deployment template path
            conf_file_path (str): Configuration file path
            bucket_name (str): Name of the GCS bucket

        Returns:
            bool: Whether or not the deployment was successful
            str: Deployment name
        """
        success, deployment_name = super(ForsetiServerInstaller, self).deploy(
            deployment_tpl_path, conf_file_path, bucket_name)

        if success:
            self.has_roles_script = gcloud.grant_server_svc_acct_roles(
                self.enable_write_access,
                self.access_target,
                self.target_id,
                self.project_id,
                self.gsuite_service_account,
                self.gcp_service_account,
                self.user_can_grant_roles)

            # Merge all the old rules if necessary
            if self.migrate_from_v1:
                self.merge_old_rules()

            # Copy the rule directory to the GCS bucket
            files.copy_file_to_destination(
                constants.RULES_DIR_PATH, bucket_name,
                is_directory=True, dry_run=self.config.dry_run)

            self.print_copy_statement(constants.RULES_DIR_PATH, bucket_name)

            # Waiting for VM to be initialized
            instance_name = '{}-vm'.format(deployment_name)
            self.wait_until_vm_initialized(instance_name)

            # Create firewall rules
            self.create_firewall_rules()

        return success, deployment_name

    def merge_old_rules(self):
        """Merge old rules to new rules."""
        for v1_rule in self.v1_config.rules:
            new_rule_path = os.path.join(constants.RULES_DIR_PATH,
                                         v1_rule.file_name)
            new_rule = files.read_yaml_file_from_local(new_rule_path)
            field_identifiers = {'rules': ['name', 'rule_id'],
                                 'default_identifier': 'name',
                                 'resource': 'type',
                                 'bindings': 'role',
                                 'rule_groups': 'group_id'}
            utils.merge_object(new_rule, v1_rule.data, fields_to_ignore=[],
                               field_identifiers=field_identifiers)
            files.write_data_to_yaml_file(new_rule, new_rule_path)

    def create_firewall_rules(self):
        """Create firewall rules for Forseti server instance."""
        # Rule to block out all the ingress traffic
        gcloud.create_firewall_rule(
            self.format_firewall_rule_name('forseti-server-deny-all'),
            [self.gcp_service_account],
            constants.FirewallRuleAction.DENY,
            ['icmp', 'udp', 'tcp'],
            constants.FirewallRuleDirection.INGRESS,
            1)

        # Rule to open only port tcp:50051
        # within the internal network (ip-ranges - 10.128.0.0/9)
        gcloud.create_firewall_rule(
            self.format_firewall_rule_name('forseti-server-allow-grpc'),
            [self.gcp_service_account],
            constants.FirewallRuleAction.ALLOW,
            ['tcp:50051'],
            constants.FirewallRuleDirection.INGRESS,
            0,
            '10.128.0.0/9')

    def generate_forseti_conf(self):
        """Generate Forseti conf file.

        if self.migrate_from_v1 is True, pull the v1 configuration
        file and merge it with v2 template

        Returns:
            str: Forseti configuration file path
        """
        forseti_conf_path = super(ForsetiServerInstaller,
                                  self).generate_forseti_conf()

        if self.migrate_from_v1:
            new_conf = files.read_yaml_file_from_local(forseti_conf_path)
            fields_to_ignore = ['db_host', 'db_user', 'db_name',
                                'inventory', 'output_path', 'gcs_path']
            field_identifiers = {'scanners' : 'name', 'resources': 'resource'}
            utils.merge_object(new_conf, self.v1_config.config,
                               fields_to_ignore, field_identifiers)
            files.write_data_to_yaml_file(new_conf, forseti_conf_path)

        return forseti_conf_path

    def format_firewall_rule_name(self, rule_name):
        """Format firewall rule name.

        Args:
            rule_name (str): Name of the firewall rule

        Returns:
            str: Firewall rule name
        """
        return '{}-{}'.format(rule_name, self.config.datetimestamp)

    def should_grant_access(self):
        """Inform user that they need IAM access to grant Forseti access."""
        utils.print_banner('Current IAM access')
        choice = None

        if not self.config.advanced_mode:
            choice = 'y'

        while choice != 'y' and choice != 'n':
            choice = raw_input(constants.QUESTION_ACCESS_TO_GRANT_ROLES.format(
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
        bucket_name = self.generate_bucket_name()
        return {
            'CLOUDSQL_REGION': self.config.cloudsql_region,
            'CLOUDSQL_INSTANCE_NAME': self.config.cloudsql_instance,
            'SCANNER_BUCKET': bucket_name[len('gs://'):],
            'BUCKET_LOCATION': self.config.bucket_location,
            'GCP_SERVER_SERVICE_ACCOUNT': self.gcp_service_account,
            'GSUITE_SERVICE_ACCOUNT': self.gsuite_service_account,
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
        bucket_name = self.generate_bucket_name()
        return {
            'EMAIL_RECIPIENT': self.config.notification_recipient_email,
            'EMAIL_SENDER': self.config.notification_sender_email,
            'SENDGRID_API_KEY': self.config.sendgrid_api_key,
            'SCANNER_BUCKET': bucket_name[len('gs://'):],
            'DOMAIN_SUPER_ADMIN_EMAIL': self.config.gsuite_superadmin_email
        }

    def determine_access_target(self):
        """Determine where to enable Forseti access.

        Either org, folder, or project level.
        """
        utils.print_banner('Forseti access target')

        if not self.config.advanced_mode:
            self.access_target = constants.RESOURCE_TYPES[0]
            self.target_id = self.organization_id

        while not self.target_id:
            if self.setup_explain:
                # If user wants to setup Explain, they must setup
                # access on an organization.
                choice_index = 1
            else:
                try:
                    print(constants.MESSAGE_FORSETI_CONFIGURATION_ACCESS_LEVEL)
                    for (i, choice) in enumerate(constants.RESOURCE_TYPES):
                        print('[%s] %s' % (i+1, choice))
                    choice_input = raw_input(
                        constants.QUESTION_FORSETI_CONFIGURATION_ACCESS_LEVEL
                    ).strip()
                    choice_index = int(choice_input)
                except ValueError:
                    print('Invalid choice, try again.')
                    continue

            if choice_index and choice_index <= len(constants.RESOURCE_TYPES):
                self.access_target = constants.RESOURCE_TYPES[choice_index-1]
                if self.access_target == 'organization':
                    self.target_id = gcloud.choose_organization()
                elif self.access_target == 'folder':
                    self.target_id = gcloud.choose_folder(self.organization_id)
                else:
                    self.target_id = gcloud.choose_project()

        self.resource_root_id = utils.format_resource_id(
            '%ss' % self.access_target, self.target_id)

        print('Forseti will be granted access to: %s' %
              self.resource_root_id)

    def get_email_settings(self):
        """Ask user for specific setup values."""
        if not self.config.sendgrid_api_key:
            # Ask for SendGrid API Key
            print(constants.MESSAGE_ASK_SENDGRID_API_KEY)
            self.config.sendgrid_api_key = raw_input(
                constants.QUESTION_SENDGRID_API_KEY).strip()
        if self.config.sendgrid_api_key:
            if not self.config.notification_sender_email:
                self.config.notification_sender_email = (
                    constants.NOTIFICATION_SENDER_EMAIL)

            # Ask for notification recipient email
            if not self.config.notification_recipient_email:
                self.config.notification_recipient_email = raw_input(
                    constants.QUESTION_NOTIFICATION_RECIPIENT_EMAIL).strip()

        while not self.config.gsuite_superadmin_email:
            # User has to enter a G Suite super admin email
            print(constants.MESSAGE_ASK_GSUITE_SUPERADMIN_EMAIL)
            self.config.gsuite_superadmin_email = raw_input(
                constants.QUESTION_GSUITE_SUPERADMIN_EMAIL).strip()

    def format_gsuite_service_acct_id(self):
        """Format the gsuite service account id"""
        self.gsuite_service_account = utils.format_service_acct_id(
            'gsuite',
            'reader',
            self.config.timestamp,
            self.project_id)

    def format_gcp_service_acct_id(self):
        """Format the service account ids."""
        modifier = 'reader'
        if self.enable_write_access:
            modifier = 'readwrite'

        self.gcp_service_account = utils.format_service_acct_id(
            'gcp',
            modifier,
            self.config.timestamp,
            self.project_id)

    def should_enable_write_access(self):
        """Ask if user wants to enable write access for Forseti."""
        utils.print_banner('Enable Forseti write access')
        choice = None
        if not self.config.advanced_mode:
            choice = 'y'

        while choice != 'y' and choice != 'n':
            choice = raw_input(
                constants.QUESTION_ENABLE_WRITE_ACCESS).strip().lower()

        if choice == 'y':
            self.enable_write_access = True
            print('Forseti will have write access on %s.' %
                  self.resource_root_id)

    def post_install_instructions(self, deploy_success, deployment_name,
                                  deployment_tpl_path, forseti_conf_path,
                                  bucket_name):

        super(ForsetiServerInstaller, self).post_install_instructions(
            deploy_success, deployment_name,
            deployment_tpl_path, forseti_conf_path,
            bucket_name)
        if self.has_roles_script:
            print(constants.MESSAGE_HAS_ROLE_SCRIPT.format(
                self.resource_root_id))

        if not self.config.sendgrid_api_key:
            print(constants.MESSAGE_SKIP_EMAIL)

        if self.config.gsuite_superadmin_email:
            print(constants.MESSAGE_GSUITE_DATA_COLLECTION.format(
                self.project_id,
                self.organization_id,
                self.gsuite_service_account))
        else:
            print(constants.MESSAGE_ENABLE_GSUITE_GROUP)
