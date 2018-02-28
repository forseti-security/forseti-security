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

from configs.config import Config
from util import constants
from util import files
from util import gcloud
from util import utils


class ForsetiInstaller(object):
    """Forseti installer base class (abstract)"""
    __metaclass__ = ABCMeta

    # Class variables initialization
    branch = None
    project_id = None
    organization_id = None
    gcp_service_acct_email = None
    user_can_grant_roles = True
    config = Config()

    @abstractmethod
    def __init__(self):
        """Initialize."""
        pass

    def run_setup(self):
        """Run the setup steps."""
        utils.print_banner('Installing Forseti {} v{}'.format(
            self.config.installation_type, utils.get_forseti_version()))

        # Preflight checks.
        self.preflight_checks()

        # Create/Reuse service account(s).
        self.create_or_reuse_service_accts()

        # Create configuration file and deployment template.
        (conf_file_path,
         deployment_tpl_path) = self.create_resource_files()

        # Deployment.
        bucket_name = self.generate_bucket_name()
        deploy_success, deployment_name = self.deploy(deployment_tpl_path,
                                                      conf_file_path,
                                                      bucket_name)

        # After deployment.
        self.post_install_instructions(deploy_success,
                                       deployment_name,
                                       deployment_tpl_path,
                                       conf_file_path,
                                       bucket_name)

    def create_resource_files(self):
        """Create configuration file and deployment template.

        Returns:
            str: Configuration file path.
            str: Deployment template path.
        """
        utils.print_banner('Creating configuration file and'
                           ' deployment template')
        conf_file_path = self.generate_forseti_conf()
        deployment_tpl_path = self.generate_deployment_templates()

        return conf_file_path, deployment_tpl_path

    def preflight_checks(self):
        """Pre-flight checks"""
        self.check_run_properties()
        self.branch = utils.infer_version(self.config.advanced_mode)
        self.project_id, authed_user, is_cloudshell = gcloud.get_gcloud_info()
        gcloud.verify_gcloud_information(self.project_id,
                                         authed_user,
                                         self.config.force_no_cloudshell,
                                         is_cloudshell)
        self.organization_id = gcloud.lookup_organization(self.project_id)
        gcloud.check_billing_enabled(self.project_id, self.organization_id)

    def create_or_reuse_service_accts(self):
        """Create or reuse service accounts."""
        utils.print_banner('Creating/Reusing service account(s)')
        gcp_service_acct_email, gcp_service_acct_name = (
            self.format_gcp_service_acct_id())
        self.gcp_service_acct_email = gcloud.create_or_reuse_service_acct(
            'gcp_service_account',
            gcp_service_acct_name,
            gcp_service_acct_email,
            self.config.advanced_mode,
            self.config.dry_run)

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
        deployment_name, return_code = gcloud.create_deployment(
            self.project_id,
            self.organization_id,
            deployment_tpl_path,
            self.config.installation_type,
            self.config.datetimestamp,
            self.config.dry_run)

        deployment_completed = not return_code

        if deployment_completed:
            # If deployed successfully, make sure the VM has been initialized,
            # copy configuration file, deployment template file and
            # rule files to the GCS bucket

            if self.config.dry_run:
                print('This is a dry run, will not copy any files.')

            utils.print_banner('Copying configuration file/deployment'
                               ' template to GCS')

            conf_output_path = constants.FORSETI_CONF_PATH.format(
                bucket_name=bucket_name,
                installation_type=self.config.installation_type)

            print('Copying {} to {}'.format(conf_file_path, conf_output_path))

            files.copy_file_to_destination(
                conf_file_path, conf_output_path,
                is_directory=False, dry_run=self.config.dry_run)

            deployment_tpl_output_path = (
                constants.DEPLOYMENT_TEMPLATE_OUTPUT_PATH.format(bucket_name))

            print('Copying {} to {}'.format(deployment_tpl_path,
                                            deployment_tpl_output_path))

            files.copy_file_to_destination(
                deployment_tpl_path, deployment_tpl_output_path,
                is_directory=False, dry_run=self.config.dry_run)

        return deployment_completed, deployment_name

    def wait_until_vm_initialized(self, vm_name):
        """Check vm init status.

        Args:
            vm_name (str): Name of the VM instance.
        """

        installation_type = self.config.installation_type.capitalize()
        utils.print_banner('{} VM Initialization'.format(installation_type))
        _, zone, name = gcloud.get_vm_instance_info(vm_name)

        # VT100 control codes, use to remove the last line
        erase_line = '\x1b[2K'

        for i in range(0, constants.MAXIMUM_LOOP_COUNT):
            dots = '.' * (i % 10)
            sys.stdout.write('\r{}This may take a few minutes. '
                             'Waiting for Forseti {} to start{}'
                             .format(erase_line, installation_type, dots))
            sys.stdout.flush()
            if gcloud.check_vm_init_status(name, zone):
                break
        # print new line
        print ('Done.\n')

    def check_run_properties(self):
        """Check script run properties."""
        print('Dry run? %s' % self.config.dry_run)
        print('Advanced mode? %s' % self.config.advanced_mode)

    def format_gcp_service_acct_id(self):
        """Format the service account ids.

        Returns:
            str: GCP service account email.
            str: GCP service account name.
        """
        service_account_email, service_account_name = (
            utils.generate_service_acct_info(
                'gcp',
                'reader',
                self.config.installation_type,
                self.config.timestamp,
                self.project_id))
        return service_account_email, service_account_name

    def generate_bucket_name(self):
        """Generate GCS bucket name.

        Returns:
            str: Name of the GCS bucket
        """
        return constants.DEFAULT_BUCKET_FMT_V2.format(
            self.config.installation_type,
            self.config.timestamp)

    @abstractmethod
    def get_deployment_values(self):
        """Get deployment values

        Returns:789
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
            self.config.timestamp)

        print('\nCreated deployment template:\n    %s\n' %
              deployment_tpl_path)
        return deployment_tpl_path

    def generate_forseti_conf(self):
        """Generate Forseti conf file.

        Returns:
            str: Forseti configuration file path
        """
        # Create a forseti_conf_{INSTALLATION_TYPE}_$TIMESTAMP.yaml config file
        # with values filled in.

        conf_values = self.get_configuration_values()

        forseti_conf_path = files.generate_forseti_conf(
            self.config.installation_type,
            conf_values,
            self.config.datetimestamp)

        print('\nCreated Forseti {} configuration file:\n    {}\n'.
              format(self.config.installation_type,
                     forseti_conf_path))
        return forseti_conf_path

    def post_install_instructions(self, deploy_success, deployment_name,
                                  deployment_tpl_path, forseti_conf_path,
                                  bucket_name):
        """Show post-install instructions.

        Print link for deployment manager dashboard
        Print link to go to G Suite service account and enable DWD

        Args:
            deploy_success (bool): Whether deployment was successful
            deployment_name (str): Name of the deployment
            deployment_tpl_path (str): Deployment template path
            forseti_conf_path (str): Forseti configuration file path
            bucket_name (str): Name of the GCS bucket
        """
        utils.print_banner('Forseti {} post-setup instructions'
                           .format(self.config.installation_type))

        if self.config.dry_run:
            print('This was a dry run, so a deployment was not attempted. '
                  'You can still create the deployment manually.\n')
        elif deploy_success:
            print(constants.MESSAGE_FORSETI_BRANCH_DEPLOYED.format(
                self.branch))
        else:
            print(constants.MESSAGE_DEPLOYMENT_HAD_ISSUES)

        deploy_tpl_gcs_path = constants.DEPLOYMENT_TEMPLATE_OUTPUT_PATH.format(
            bucket_name)

        print(constants.MESSAGE_DEPLOYMENT_TEMPLATE_LOCATION.format(
            deployment_tpl_path, deploy_tpl_gcs_path))

        if self.config.dry_run:
            print(constants.MESSAGE_FORSETI_CONFIGURATION_GENERATED_DRY_RUN
                  .format(forseti_conf_path, bucket_name))
        else:
            print(constants.MESSAGE_VIEW_DEPLOYMENT_DETAILS.format(
                deployment_name,
                self.project_id,
                self.organization_id))

            print(constants.MESSAGE_FORSETI_CONFIGURATION_GENERATED.format(
                installation_type=self.config.installation_type,
                datetimestamp=self.config.datetimestamp,
                bucket_name=bucket_name))
