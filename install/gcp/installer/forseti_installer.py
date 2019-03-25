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

""" Forseti Installer."""

from __future__ import print_function
from abc import ABCMeta
from abc import abstractmethod

import sys

from util import constants
from util import files
from util import gcloud
from util import installer_errors
from util import utils


class ForsetiInstructions(object):
    """Forseti setup instructions."""

    def __init__(self):
        """Init."""
        self.deployed_branch = ''
        self.deployment_templates = []
        self.configurations = []
        self.other_messages = []

    def merge_head(self, other_instruction):
        """Merge instructions, input instructions will be merged to the head
        of the current instructions.

        Args:
            other_instruction (ForsetiInstructions): The other instructions.
        """
        self.deployed_branch = other_instruction.deployed_branch
        self.deployment_templates = (
            other_instruction.deployment_templates + self.deployment_templates)
        self.configurations = (
            other_instruction.configurations + self.configurations)
        self.other_messages = (other_instruction.other_messages +
                               self.other_messages)

    def __str__(self):
        """Str.

        Returns:
            str: String representation of ForsetiInstructions.
        """
        message = self.deployed_branch

        deployment_template_gcs_paths = '\t' + '\n\t'.join(
            self.deployment_templates)
        message += constants.MESSAGE_DEPLOYMENT_TEMPLATE_LOCATION.format(
            deployment_template_gcs_paths=deployment_template_gcs_paths)

        configuration_paths = '\t' + '\n\t'.join(self.configurations)
        message += constants.MESSAGE_FORSETI_CONFIGURATION_GENERATED.format(
            forseti_config_file_paths=configuration_paths
        )

        message += '\n'.join(self.other_messages)

        return message


class ForsetiInstaller(object):
    """Forseti installer base class (abstract)"""
    __metaclass__ = ABCMeta

    # Class variables initialization
    version = None
    project_id = None
    organization_id = None
    composite_root_resources = []
    gcp_service_acct_email = None
    user_can_grant_roles = True

    @abstractmethod
    def __init__(self, config=None, previous_installer=None):
        """Initialize.

        Args:
            config (Config): The configuration object.
            previous_installer (ForsetiInstaller): The previous ran installer,
                we can get the installer environment information from it.
        """
        self.config = config
        if previous_installer:
            self.populate_installer_environment(previous_installer)
        gcloud.set_network_host_project_id(self)

    def run_setup(self,
                  setup_continuation=False,
                  final_setup=True,
                  previous_instructions=None):
        """Run the setup steps.

        If setup_continuation is True, we don't need to run the pre-flight
        checks any more because it has been done in the previous installation.

        Args:
            setup_continuation (bool): If this is a continuation of the
                previous setup.
            final_setup (bool): The final setup.
            previous_instructions (ForsetiInstructions): Post installation
                instructions from previous installation.

        Returns:
            ForsetiInstructions: Forseti instructions.
        """
        utils.print_installation_header('Installing Forseti {}'.format(
            self.config.installation_type.capitalize()))

        if not setup_continuation:
            self.preflight_checks()

        # Create/Reuse service account(s).
        self.create_or_reuse_service_accts()

        # Create configuration file and deployment template.
        (conf_file_path,
         deployment_tpl_path) = self.create_resource_files()

        # Deployment.
        bucket_name = self.generate_bucket_name()
        deploy_success, _ = self.deploy(deployment_tpl_path,
                                        conf_file_path,
                                        bucket_name)

        # After deployment.
        instructions = self.post_install_instructions(deploy_success,
                                                      bucket_name)

        if previous_instructions is not None:
            instructions.merge_head(previous_instructions)

        if final_setup:
            utils.print_banner('Forseti Post-Setup Instructions')
            print(instructions)

        return instructions

    def create_resource_files(self):
        """Create configuration file and deployment template.

        Returns:
            str: Configuration file path.
            str: Deployment template path.
        """
        conf_file_path = self.generate_forseti_conf()
        deployment_tpl_path = self.generate_deployment_templates()

        return conf_file_path, deployment_tpl_path

    @staticmethod
    def check_if_authed_user_in_domain(organization_id, authed_user):
        """Check if the authed user is in the current domain.

        If authed user is not in the current domain that Forseti is being
        installed to, then user needs to be warned to add an additional
        osLoginExternalUser role, in order to have ssh access to the
        client VM.

        Args:
            organization_id (str): Id of the organization.
            authed_user (str): Email of the user that is currently
                authenticated in gcloud.
        """
        domain = gcloud.get_domain_from_organization_id(
            organization_id)
        if domain not in authed_user:
            choice = ''
            while choice != 'y' and choice != 'n':
                choice = raw_input(
                    constants.QUESTION_CONTINUE_IF_AUTHED_USER_IS_NOT_IN_DOMAIN)
            choice = choice.lower()
            if choice == 'n':
                sys.exit(1)

    def preflight_checks(self):
        """Pre-flight checks"""
        utils.print_banner('Pre-installation checks')
        self.version = utils.infer_version()
        self.composite_root_resources = self.config.composite_root_resources
        service_account_key_file = self.config.service_account_key_file
        if self.config.project_id:
            gcloud.set_project_id(self.config.project_id)

        self.project_id, authed_user, is_cloudshell = gcloud.get_gcloud_info()
        gcloud.verify_gcloud_information(self.project_id,
                                         authed_user,
                                         self.config.force_no_cloudshell,
                                         is_cloudshell)
        self.organization_id = gcloud.lookup_organization(self.project_id)
        self.config.generate_identifier(self.organization_id)

        if not service_account_key_file:
            self.check_if_authed_user_in_domain(
                self.organization_id, authed_user)
        else:
            gcloud.activate_service_account(service_account_key_file)

        gcloud.check_billing_enabled(self.project_id, self.organization_id)

    def create_or_reuse_service_accts(self):
        """Create or reuse service accounts."""
        utils.print_banner('Creating/Reusing Service Account(s)')
        gcp_service_acct_email, gcp_service_acct_name = (
            self.format_gcp_service_acct_id())
        self.gcp_service_acct_email = gcloud.create_or_reuse_service_acct(
            'GCP Service Account',
            gcp_service_acct_name,
            gcp_service_acct_email)

    def deploy(self, deployment_tpl_path, conf_file_path, bucket_name):
        """Deploy Forseti using the deployment template

        Args:
            deployment_tpl_path (str): Deployment template path
            conf_file_path (str): Configuration file path
            bucket_name (str): Name of the GCS bucket

        Returns:
            bool: Whether or not the deployment was successful
            str: Deployment name
        """
        deployment_name = gcloud.create_deployment(
            self.project_id,
            self.organization_id,
            deployment_tpl_path,
            self.config.installation_type,
            self.config.identifier)

        status_checker = (lambda: gcloud.check_deployment_status(
            deployment_name, constants.DeploymentStatus.DONE))
        loading_message = 'Waiting for deployment to be completed...'
        deployment_completed = utils.start_loading(
            max_loading_time=900,
            exit_condition_checker=status_checker,
            message=loading_message)

        if not deployment_completed:
            # If after 15 mins and the deployment is still not completed, there
            # is something wrong with the deployment.
            print ('Deployment failed.')
            sys.exit(1)

        if deployment_completed:
            # If deployed successfully, make sure the VM has been initialized,
            # copy configuration file, deployment template file and
            # rule files to the GCS bucket

            utils.print_banner('Backing Up Important Files To GCS')

            conf_output_path = constants.FORSETI_CONF_PATH.format(
                bucket_name=bucket_name,
                installation_type=self.config.installation_type)

            print('Copying the Forseti {} configuration file to:\n\t{}'
                  .format(self.config.installation_type, conf_output_path))

            files.copy_file_to_destination(
                conf_file_path, conf_output_path,
                is_directory=False)

            deployment_tpl_output_path = (
                constants.DEPLOYMENT_TEMPLATE_OUTPUT_PATH.format(bucket_name))

            print('Copying the Forseti {} deployment template to:\n\t{}'
                  .format(self.config.installation_type,
                          deployment_tpl_output_path))

            files.copy_file_to_destination(
                deployment_tpl_path, deployment_tpl_output_path,
                is_directory=False)

        return deployment_completed, deployment_name

    def wait_until_vm_initialized(self, vm_name):
        """Check vm init status.

        Args:
            vm_name (str): Name of the VM instance.
        """

        installation_type = self.config.installation_type
        utils.print_banner('Forseti {} VM Initialization'.format(
            installation_type.capitalize()))
        _, zone, name = gcloud.get_vm_instance_info(vm_name)

        status_checker = (lambda: gcloud.check_vm_init_status(name, zone))

        loading_message = ('Waiting for Forseti {} to be initialized...'
                           .format(installation_type))

        try:
            _ = utils.start_loading(
                max_loading_time=constants.MAXIMUM_LOADING_TIME_IN_SECONDS,
                exit_condition_checker=status_checker,
                message=loading_message)
        except installer_errors.SSHError:
            # There is problem when SSHing to the VM, maybe there is a
            # firewall rule setting that is blocking the SSH from the
            # cloud shell. We will skip waiting for the VM to be initialized.
            pass

    def format_gcp_service_acct_id(self):
        """Format the service account ids.

        Returns:
            str: GCP service account email.
            str: GCP service account name.
        """
        service_account_email, service_account_name = (
            utils.generate_service_acct_info(
                'gcp',
                self.config.installation_type,
                self.config.identifier,
                self.project_id))
        return service_account_email, service_account_name

    def generate_bucket_name(self):
        """Generate GCS bucket name.

        Returns:
            str: Name of the GCS bucket
        """
        return constants.DEFAULT_BUCKET_FMT_V2.format(
            self.config.installation_type,
            self.config.identifier)

    @abstractmethod
    def get_deployment_values(self):
        """Get deployment values

        Returns:
            dict: A dictionary of values needed to generate
                the forseti deployment template
        """
        return {}

    @abstractmethod
    def get_configuration_values(self):
        """Get configuration values

        Returns:
            dict: A dictionary of values needed to generate
                the forseti configuration file
        """
        return {}

    def generate_deployment_templates(self):
        """Generate deployment templates.

        Returns:
            str: Deployment template path
        """
        deploy_values = self.get_deployment_values()

        deployment_tpl_path = files.generate_deployment_templates(
            self.config.installation_type,
            deploy_values,
            self.config.identifier)

        return deployment_tpl_path

    def generate_forseti_conf(self):
        """Generate Forseti conf file.

        Returns:
            str: Forseti configuration file path
        """
        # Create a forseti_conf_{INSTALLATION_TYPE}_$TIMESTAMP.yaml config file
        # with values filled in.

        conf_values = self.get_configuration_values()

        return files.generate_forseti_conf(
            self.config.installation_type,
            conf_values,
            self.config.identifier)

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

        instructions = ForsetiInstructions()
        if deploy_success:
            instructions.deployed_branch = (
                constants.MESSAGE_FORSETI_BRANCH_DEPLOYED.format(self.version))
        else:
            instructions.deployed_branch = (
                constants.MESSAGE_DEPLOYMENT_HAD_ISSUES)

        deploy_tpl_gcs_path = constants.DEPLOYMENT_TEMPLATE_OUTPUT_PATH.format(
            bucket_name)

        instructions.deployment_templates.append(deploy_tpl_gcs_path)

        forseti_gcs_path = (
            '{gcs_bucket}/configs/'
            'forseti_conf_{installation_type}.yaml').format(
                gcs_bucket=bucket_name,
                installation_type=self.config.installation_type
            )
        instructions.configurations.append(forseti_gcs_path)
        return instructions

    def populate_installer_environment(self, other_installer):
        """Populate the current installer environment from a given installer.

        Args:
            other_installer (ForsetiInstaller): The other installer.
        """
        self.version = other_installer.version
        self.project_id = other_installer.project_id
        self.organization_id = other_installer.organization_id

    def format_firewall_rule_name(self, rule_name):
        """Format firewall rule name.

        Args:
            rule_name (str): Name of the firewall rule.

        Returns:
            str: Firewall rule name.
        """
        return '{}-{}'.format(rule_name, self.config.identifier)
