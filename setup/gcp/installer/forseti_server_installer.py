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
from util import merge_engine
from util import utils
from util import upgradeable_resources


class ForsetiServerInstaller(ForsetiInstaller):
    """Forseti server installer."""

    # pylint: disable=too-many-instance-attributes

    gsuite_service_acct_email = None
    has_roles_script = False
    setup_explain = True
    enable_write_access = False
    resource_root_id = None
    access_target = None
    target_id = None
    migrate_from_v1 = False

    def __init__(self, **kwargs):
        """Init.

        Args:
            kwargs (dict): The kwargs.
        """
        super(ForsetiServerInstaller, self).__init__()
        self.config = ServerConfig(**kwargs)
        self.v1_config = None

    def preflight_checks(self):
        """Pre-flight checks for server instance."""

        super(ForsetiServerInstaller, self).preflight_checks()
        gcloud.enable_apis(self.config.dry_run)
        forseti_v1_name = None
        if not self.config.dry_run:
            _, zone, forseti_v1_name = gcloud.get_vm_instance_info(
                constants.REGEX_MATCH_FORSETI_V1_INSTANCE_NAME, try_match=True)
        if forseti_v1_name:
            utils.print_banner('Found a v1 installation:'
                               ' importing configuration and rules.')
            # v1 instance exists, ask if the user wants to port
            # the conf/rules settings from v1.
            self.prompt_v1_configs_migration()
        if self.migrate_from_v1:
            self.v1_config = upgradeable_resources.ForsetiV1Configuration(
                self.project_id, forseti_v1_name, zone)
            self.v1_config.fetch_information_from_gcs()
            self.populate_config_info_from_v1()
        self.determine_access_target()
        self.should_enable_write_access()
        self.should_grant_access()
        self.get_email_settings()

    def create_or_reuse_service_accts(self):
        """Create or reuse service accounts."""
        super(ForsetiServerInstaller, self).create_or_reuse_service_accts()
        gsuite_service_acct_email, gsuite_service_acct_name = (
            self.format_gsuite_service_acct_id())
        self.gsuite_service_acct_email = gcloud.create_or_reuse_service_acct(
            'gsuite_service_account',
            gsuite_service_acct_name,
            gsuite_service_acct_email,
            self.config.advanced_mode,
            self.config.dry_run)

    def prompt_v1_configs_migration(self):
        """Ask the user if they want to migrate conf/rule files
        from v1 to v2."""
        choice = ''
        while choice != 'y' and choice != 'n':
            choice = raw_input(
                constants.QUESTION_SHOULD_MIGRATE_FROM_V1).lower()
        self.migrate_from_v1 = choice == 'y'

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
            deployment_tpl_path (str): Deployment template path.
            conf_file_path (str): Configuration file path.
            bucket_name (str): Name of the GCS bucket.

        Returns:
            bool: Whether or not the deployment was successful.
            str: Deployment name.
        """
        success, deployment_name = super(ForsetiServerInstaller, self).deploy(
            deployment_tpl_path, conf_file_path, bucket_name)

        if success:
            # Fill in the default values for all the rule files
            default_rule_values = self.get_rule_default_values()
            files.update_rule_files(default_rule_values,
                                    constants.RULES_DIR_PATH)

            # Replace new rules if necessary.
            if self.migrate_from_v1:
                self.replace_with_old_rules()

            print('Copying {} to {}'.format(constants.RULES_DIR_PATH,
                                            bucket_name))

            # Copy the rule directory to the GCS bucket.
            files.copy_file_to_destination(
                constants.RULES_DIR_PATH, bucket_name,
                is_directory=True, dry_run=self.config.dry_run)

            self.has_roles_script = gcloud.grant_server_svc_acct_roles(
                self.enable_write_access,
                self.access_target,
                self.target_id,
                self.project_id,
                self.gsuite_service_acct_email,
                self.gcp_service_acct_email,
                self.user_can_grant_roles)

            # Waiting for VM to be initialized.
            instance_name = '{}-vm'.format(deployment_name)
            self.wait_until_vm_initialized(instance_name)

            # Create firewall rules.
            self.create_firewall_rules()

        return success, deployment_name

    def replace_with_old_rules(self):
        """Replace new rules with old rules.

        This is very specific for migration from v1 to v2 because we don't
        want to modify the rule files that user defined in v1.
        """
        for v1_rule in self.v1_config.rules:
            new_rule_path = os.path.join(constants.RULES_DIR_PATH,
                                         v1_rule.file_name)
            files.write_data_to_yaml_file(v1_rule, new_rule_path)

    def create_firewall_rules(self):
        """Create firewall rules for Forseti server instance."""
        # Rule to block out all the ingress traffic.
        gcloud.create_firewall_rule(
            self.format_firewall_rule_name('forseti-server-deny-all'),
            [self.gcp_service_acct_email],
            constants.FirewallRuleAction.DENY,
            ['icmp', 'udp', 'tcp'],
            constants.FirewallRuleDirection.INGRESS,
            1)

        # Rule to open only port tcp:50051 within the
        # internal network (ip-ranges - 10.128.0.0/9).
        gcloud.create_firewall_rule(
            self.format_firewall_rule_name('forseti-server-allow-grpc'),
            [self.gcp_service_acct_email],
            constants.FirewallRuleAction.ALLOW,
            ['tcp:50051'],
            constants.FirewallRuleDirection.INGRESS,
            0,
            '10.128.0.0/9')

        # Create firewall rule to open only port tcp:22 (ssh)
        # to all the external traffics from the internet.
        gcloud.create_firewall_rule(
            self.format_firewall_rule_name(
                'forseti-server-allow-ssh-external'),
            [self.gcp_service_acct_email],
            constants.FirewallRuleAction.ALLOW,
            ['tcp:22'],
            constants.FirewallRuleDirection.INGRESS,
            0,
            '0.0.0.0/0')

    def generate_forseti_conf(self):
        """Generate Forseti conf file.

        If self.migrate_from_v1 is True, pull the v1 configuration
        file and merge it with v2 template.

        Returns:
            str: Forseti configuration file path.
        """

        forseti_conf_path = super(
            ForsetiServerInstaller, self).generate_forseti_conf()

        if self.migrate_from_v1:
            new_conf = files.read_yaml_file_from_local(forseti_conf_path)
            fields_to_ignore = [
                'db_host', 'db_user', 'db_name',
                'inventory', 'output_path', 'gcs_path',
                'groups_service_account_key_file',
                'domain_super_admin_email',
                'max_admin_api_calls_per_100_seconds',
                'max_appengine_api_calls_per_second',
                'max_bigquery_api_calls_per_100_seconds',
                'max_cloudbilling_api_calls_per_60_seconds',
                'max_compute_api_calls_per_second',
                'max_container_api_calls_per_100_seconds',
                'max_crm_api_calls_per_100_seconds',
                'max_iam_api_calls_per_second',
                'max_results_admin_api',
                'max_sqladmin_api_calls_per_100_seconds']
            field_identifiers = {'scanners': 'name',
                                 'resources': 'resource',
                                 'pipelines': 'name'}
            merge_engine.merge_object(merge_from=self.v1_config.config,
                                      merge_to=new_conf,
                                      fields_to_ignore=fields_to_ignore,
                                      field_identifiers=field_identifiers)

            # Fields that have changed categories cannot be merged,
            # swap them here instead.
            self._swap_config_fields(new_conf, self.v1_config.config)

            files.write_data_to_yaml_file(new_conf, forseti_conf_path)

        return forseti_conf_path

    def format_firewall_rule_name(self, rule_name):
        """Format firewall rule name.

        Args:
            rule_name (str): Name of the firewall rule.

        Returns:
            str: Firewall rule name.
        """
        return '{}-{}'.format(rule_name, self.config.datetimestamp)

    def should_grant_access(self):
        """Inform user that they need IAM access to grant Forseti access."""
        choice = None

        if not self.config.advanced_mode:
            choice = 'y'

        while choice != 'y' and choice != 'n':
            choice = raw_input(constants.QUESTION_ACCESS_TO_GRANT_ROLES.format(
                self.resource_root_id)).strip().lower()

        if choice == 'y':
            self.user_can_grant_roles = True
            print('Forseit will grant required roles on the target: %s' %
                  self.resource_root_id)
        else:
            self.user_can_grant_roles = False
            print('Forseit will NOT grant required roles on the target: %s' %
                  self.resource_root_id)

    def get_deployment_values(self):
        """Get deployment values.

        Returns:
            dict: A dictionary of values needed to generate
                the forseti deployment template.
        """
        bucket_name = self.generate_bucket_name()
        return {
            'CLOUDSQL_REGION': self.config.cloudsql_region,
            'CLOUDSQL_INSTANCE_NAME': self.config.cloudsql_instance,
            'SCANNER_BUCKET': bucket_name[len('gs://'):],
            'BUCKET_LOCATION': self.config.bucket_location,
            'GCP_SERVER_SERVICE_ACCOUNT': self.gcp_service_acct_email,
            'GSUITE_SERVICE_ACCOUNT': self.gsuite_service_acct_email,
            'BRANCH_OR_RELEASE': 'branch-name: "{}"'.format(self.branch),
            'rand_minute': random.randint(0, 59)
        }

    def get_configuration_values(self):
        """Get configuration values.

        Returns:
            dict: A dictionary of values needed to generate
                the forseti configuration file.
        """
        bucket_name = self.generate_bucket_name()
        return {
            'EMAIL_RECIPIENT': self.config.notification_recipient_email,
            'EMAIL_SENDER': self.config.notification_sender_email,
            'SENDGRID_API_KEY': self.config.sendgrid_api_key,
            'SCANNER_BUCKET': bucket_name[len('gs://'):],
            'DOMAIN_SUPER_ADMIN_EMAIL': self.config.gsuite_superadmin_email,
            'ROOT_RESOURCE_ID': self.resource_root_id,
        }

    def get_rule_default_values(self):
        """Get rule default values.

        Returns:
            dict: A dictionary of default values.
        """
        organization_id = self.resource_root_id.split('/')[-1]
        domain = gcloud.get_domain_from_organization_id(organization_id)
        return {
            'ORGANIZATION_ID': organization_id,
            'DOMAIN': domain
        }

    def determine_access_target(self):
        """Determine where to enable Forseti access.

        Allow only org level access since IAM explain
        requires org level access.
        """
        utils.print_banner('Forseti installation configuration')

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

        print('Forseti will be granted access on the target: %s' %
              self.resource_root_id)

    def get_email_settings(self):
        """Ask user for specific setup values."""
        utils.print_banner('Configuring email settings')
        if not self.config.sendgrid_api_key:
            # Ask for SendGrid API Key.
            print(constants.MESSAGE_ASK_SENDGRID_API_KEY)
            self.config.sendgrid_api_key = raw_input(
                constants.QUESTION_SENDGRID_API_KEY).strip()
        if self.config.sendgrid_api_key:
            if not self.config.notification_sender_email:
                self.config.notification_sender_email = (
                    constants.NOTIFICATION_SENDER_EMAIL)

            # Ask for notification recipient email.
            if not self.config.notification_recipient_email:
                self.config.notification_recipient_email = raw_input(
                    constants.QUESTION_NOTIFICATION_RECIPIENT_EMAIL).strip()

        utils.print_banner('Configuring GSuite admin information')
        while not self.config.gsuite_superadmin_email:
            # User has to enter a G Suite super admin email.
            print(constants.MESSAGE_ASK_GSUITE_SUPERADMIN_EMAIL)
            self.config.gsuite_superadmin_email = raw_input(
                constants.QUESTION_GSUITE_SUPERADMIN_EMAIL).strip()

    def format_gsuite_service_acct_id(self):
        """Format the gsuite service account id.

        Returns:
            str: GSuite service account email.
            str: GSuite service account name.
        """
        service_account_email, service_account_name = (
            utils.generate_service_acct_info(
                'gsuite',
                'reader',
                self.config.installation_type,
                self.config.timestamp,
                self.project_id))

        return service_account_email, service_account_name

    def format_gcp_service_acct_id(self):
        """Format the service account ids.

        Returns:
            str: GCP service account email.
            str: GCP service account name.
        """
        modifier = 'reader'
        if self.enable_write_access:
            modifier = 'readwrite'

        service_account_email, service_account_name = (
            utils.generate_service_acct_info(
                'gcp',
                modifier,
                self.config.installation_type,
                self.config.timestamp,
                self.project_id))

        return service_account_email, service_account_name

    def should_enable_write_access(self):
        """Ask if user wants to enable write access for Forseti."""
        choice = None
        if not self.config.advanced_mode:
            choice = 'y'

        while choice != 'y' and choice != 'n':
            choice = raw_input(
                constants.QUESTION_ENABLE_WRITE_ACCESS).strip().lower()

        if choice == 'y':
            self.enable_write_access = True
            print('Forseti will have write access on the target: %s' %
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
                self.gsuite_service_acct_email))
        else:
            print(constants.MESSAGE_ENABLE_GSUITE_GROUP)

    @staticmethod
    def _swap_config_fields(old_config, new_config):
        """Swapping fields. This will work for all v1 migrating to v2.

        Note: new_config will get modified.

        Args:
            old_config (dict): Old configuration.
            new_config (dict): New configuration.
        """

        # Some fields have been renamed from v1 to v2
        # This is a map to map names from v2 back to v1
        field_names_mapping = {
            'gsuite_service_account_key_file':
                'groups_service_account_key_file'}

        global_to_inventory = [
            'gsuite_service_account_key_file',
            'domain_super_admin_email'
        ]
        global_to_api_quota = [
            'max_admin_api_calls_per_100_seconds',
            'max_appengine_api_calls_per_second',
            'max_bigquery_api_calls_per_100_seconds',
            'max_cloudbilling_api_calls_per_60_seconds',
            'max_compute_api_calls_per_second',
            'max_container_api_calls_per_100_seconds',
            'max_crm_api_calls_per_100_seconds',
            'max_iam_api_calls_per_second',
            'max_servicemanagement_api_calls_per_100_seconds',
            'max_sqladmin_api_calls_per_100_seconds'
        ]

        new_conf_inventory = new_config['inventory']
        new_conf_api_quota = new_conf_inventory['api_quota']

        old_config_global = ({} if 'global' not in old_config
                             else old_config['global'])

        for field in global_to_inventory:
            v1_field = field_names_mapping.get(field, field)
            if v1_field in old_config_global:
                new_conf_inventory[field] = (old_config_global[v1_field]
                                             or new_conf_inventory[field])

        for field in global_to_api_quota:
            v1_field = field_names_mapping.get(field, field)
            if v1_field in old_config_global:
                new_conf_api_quota[field] = (old_config_global[v1_field]
                                             or new_conf_api_quota[field])
