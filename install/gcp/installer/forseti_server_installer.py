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
import time

from forseti_installer import ForsetiInstaller
from util import constants
from util import files
from util import gcloud
from util import utils


class ForsetiServerInstaller(ForsetiInstaller):
    """Forseti server installer."""

    gsuite_service_acct_email = None
    has_roles_script = False
    setup_explain = True
    enable_write_access = True
    resource_root_id = None
    access_target = None
    target_id = None
    composite_root_resources = []
    user_can_grant_roles = True

    firewall_rules_to_be_deleted = ['default-allow-icmp',
                                    'default-allow-internal',
                                    'default-allow-rdp',
                                    'default-allow-ssh']

    def __init__(self, config, previous_installer=None):
        """Init.

        Args:
            config (ServerConfig): The configuration object.
            previous_installer (ForsetiInstaller): The previous ran installer,
                we can get the installer environment information from it.
        """
        super(ForsetiServerInstaller, self).__init__(config,
                                                     previous_installer)

    def preflight_checks(self):
        """Pre-flight checks for server instance."""

        super(ForsetiServerInstaller, self).preflight_checks()
        self.config.generate_cloudsql_instance()
        self.get_email_settings()
        gcloud.enable_apis()
        self.determine_access_target()
        print('Forseti will be granted write access and required roles to: '
              '{}'.format(self.resource_root_id))

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
        resources = []
        if self.composite_root_resources:
            resources = self.composite_root_resources
        else:
            resources = [self.resource_root_id]

        self.has_roles_script = gcloud.grant_server_svc_acct_roles(
            self.enable_write_access,
            resources,
            self.project_id,
            self.gcp_service_acct_email,
            self.user_can_grant_roles)

        # Sleep for 10s to avoid race condition of accessing resources before
        # the permissions take hold. There is no other deterministic way to
        # verify the permissions, so using sleep.
        time.sleep(10)

        success, deployment_name = super(ForsetiServerInstaller, self).deploy(
            deployment_tpl_path, conf_file_path, bucket_name)

        if success:
            # Fill in the default values for all the rule files
            default_rule_values = self.get_rule_default_values()
            files.update_rule_files(default_rule_values,
                                    constants.RULES_DIR_PATH)

            print('Copying the default Forseti rules to:\n\t{}'.format(
                os.path.join(bucket_name, 'rules')))

            # Copy the rule directory to the GCS bucket.
            files.copy_file_to_destination(
                constants.RULES_DIR_PATH, bucket_name,
                is_directory=True)

            # Waiting for VM to be initialized.
            instance_name = 'forseti-{}-vm-{}'.format(
                self.config.installation_type,
                self.config.identifier)

            # Create firewall rules.
            self.create_firewall_rules()
            self.wait_until_vm_initialized(instance_name)

            # Delete firewall rules.
            self.delete_firewall_rules()

        return success, deployment_name

    def create_firewall_rules(self):
        """Create firewall rules for Forseti server instance."""
        # This rule overrides the implied deny for ingress
        # because it is specific to service account with a higher priority
        # that would be harder to be overriden.
        gcloud.create_firewall_rule(
            self.format_firewall_rule_name('forseti-server-deny-all'),
            [self.gcp_service_acct_email],
            constants.FirewallRuleAction.DENY,
            ['all'],
            constants.FirewallRuleDirection.INGRESS,
            200,
            self.config.vpc_host_network)

        # Rule to open only port tcp:50051 within the
        # internal network (ip-ranges - 10.128.0.0/9).
        gcloud.create_firewall_rule(
            self.format_firewall_rule_name('forseti-server-allow-grpc'),
            [self.gcp_service_acct_email],
            constants.FirewallRuleAction.ALLOW,
            ['tcp:50051'],
            constants.FirewallRuleDirection.INGRESS,
            100,
            self.config.vpc_host_network,
            '10.128.0.0/9')

        # Create firewall rule to open only port tcp:22 (ssh)
        # to all the external traffic from the internet to ssh into server VM.
        gcloud.create_firewall_rule(
            self.format_firewall_rule_name(
                'forseti-server-allow-ssh-external'),
            [self.gcp_service_acct_email],
            constants.FirewallRuleAction.ALLOW,
            ['tcp:22'],
            constants.FirewallRuleDirection.INGRESS,
            100,
            self.config.vpc_host_network,
            '0.0.0.0/0')

    def delete_firewall_rules(self):
        """Deletes default firewall rules as the forseti service account rules
        serves the purpose"""
        for rule in self.firewall_rules_to_be_deleted:
            gcloud.delete_firewall_rule(rule)
            print('Deleted:', rule)

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
            'FORSETI_BUCKET': bucket_name[len('gs://'):],
            'FORSETI_CAI_BUCKET': self._get_cai_bucket_name(),
            'BUCKET_LOCATION': self.config.bucket_location,
            'GCP_SERVER_SERVICE_ACCOUNT': self.gcp_service_acct_email,
            'FORSETI_SERVER_REGION': self.config.cloudsql_region,
            'FORSETI_SERVER_ZONE': self.config.cloudsql_region + '-c',
            'VPC_HOST_PROJECT_ID': self.config.vpc_host_project_id,
            'VPC_HOST_NETWORK': self.config.vpc_host_network,
            'VPC_HOST_SUBNETWORK': self.config.vpc_host_subnetwork,
            'FORSETI_VERSION': self.version,
            'RAND_MINUTE': random.randint(0, 59)
        }

    def get_configuration_values(self):
        """Get configuration values.

        Returns:
            dict: A dictionary of values needed to generate
                the forseti configuration file.
        """
        bucket_name = self.generate_bucket_name()

        resource_root_id = ''
        composite_root_resources = ''

        if self.composite_root_resources:
            composite_root_resources = '\n'
            for resource in self.composite_root_resources:
                composite_root_resources += '       - \"' + resource + '\"\n'
        else:
            resource_root_id = self.resource_root_id

        return {
            'CAI_ENABLED': 'organizations' in self.resource_root_id,
            'EMAIL_RECIPIENT': self.config.notification_recipient_email,
            'EMAIL_SENDER': self.config.notification_sender_email,
            'SENDGRID_API_KEY': self.config.sendgrid_api_key,
            'FORSETI_BUCKET': bucket_name[len('gs://'):],
            'FORSETI_CAI_BUCKET': self._get_cai_bucket_name(),
            'DOMAIN_SUPER_ADMIN_EMAIL': self.config.gsuite_superadmin_email,
            'ROOT_RESOURCE_ID': resource_root_id,
            'COMPOSITE_ROOT_RESOURCES': composite_root_resources,
        }

    def get_rule_default_values(self):
        """Get rule default values.

        Returns:
            dict: A dictionary of default values.
        """
        if self.composite_root_resources:
            # split element 0 into type and id
            rtype, rid = self.composite_root_resources[0].split('/')

            organization_id = gcloud.lookup_organization(rid, rtype)
        else:
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
        utils.print_banner('Forseti Installation Configuration')

        if self.composite_root_resources:
            # split element 0 into type and id
            rtype, rid = self.composite_root_resources[0].split('/')
            self.access_target = rtype
            self.target_id = rid
        else:
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
                if self.access_target == 'organizations':
                    self.target_id = gcloud.choose_organization()
                elif self.access_target == 'folders':
                    self.target_id = gcloud.choose_folder(self.organization_id)
                else:
                    self.target_id = gcloud.choose_project()

        self.resource_root_id = utils.format_resource_id(
            self.access_target, self.target_id)

    def get_email_settings(self):
        """Ask user for specific install values."""
        utils.print_banner('Configuring GSuite Admin Information')
        if not self.config.gsuite_superadmin_email:
            # Ask for GSuite Superadmin email.
            print(constants.MESSAGE_ASK_GSUITE_SUPERADMIN_EMAIL)
            self.config.gsuite_superadmin_email = raw_input(
                constants.QUESTION_GSUITE_SUPERADMIN_EMAIL).strip()

        if self.config.skip_sendgrid_config:
            print(constants.MESSAGE_SKIP_SENDGRID_API_KEY)
            return

        utils.print_banner('Configuring Forseti Email Settings')
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

    def post_install_instructions(self, deploy_success, bucket_name):
        """Show post-install instructions.

        For example: link for deployment manager dashboard and
        link to go to G Suite service account and enable DWD.

        Args:
            deploy_success (bool): Whether deployment was successful
            bucket_name (str): Name of the GCS bucket

        Returns:
            ForsetiInstructions: Forseti instructions.
        """
        instructions = (
            super(ForsetiServerInstaller, self).post_install_instructions(
                deploy_success, bucket_name))

        instructions.other_messages.append(
            constants.MESSAGE_ENABLE_GSUITE_GROUP_INSTRUCTIONS)

        if self.has_roles_script:
            instructions.other_messages.append(
                constants.MESSAGE_HAS_ROLE_SCRIPT)

        if not self.config.sendgrid_api_key:
            instructions.other_messages.append(
                constants.MESSAGE_FORSETI_SENDGRID_INSTRUCTIONS)

        instructions.other_messages.append(constants.MESSAGE_RUN_FREQUENCY)

        return instructions

    def _get_cai_bucket_name(self):
        """Get CAI bucket name.

        Returns:
            str: CAI bucket name.
        """
        return 'forseti-cai-export-{}'.format(self.config.identifier)

    @staticmethod
    def _get_gcs_path(resources):
        """Get gcs path from resources.

        Args:
            resources (list): List of resources under the notifier section in
                the forseti_config_server.yaml file.
        Returns:
            str: The gcs path.
        """
        for resource in resources:
            notifiers = resource['notifiers']
            for notifier in notifiers:
                if notifier['name'] == 'gcs_violations':
                    return notifier['configuration']['gcs_path']
        return ''
