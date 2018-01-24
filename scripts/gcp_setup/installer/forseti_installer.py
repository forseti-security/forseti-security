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

""" Forseti Installer"""

from __future__ import print_function
import datetime
import sys
from abc import ABCMeta
from abc import abstractmethod

from utils.utils import print_banner, \
    get_forseti_version, format_service_acct_id, infer_version, \
    create_deployment

from utils.constants import CONFIG_FILENAME_FMT, FORSETI_CONF_PATH, \
    RULES_DIR_PATH, DEFAULT_BUCKET_FMT, MESSAGE_FORSETI_BRANCH_DEPLOYED, \
    MESSAGE_DEPLOYMENT_HAD_ISSUES, MESSAGE_DEPLOYMENT_TEMPLATE_LOCATION,\
    MESSAGE_VIEW_DEPLOYMENT_DETAILS, MESSAGE_NO_CLOUD_SHELL, \
    MESSAGE_FORSETI_CONFIGURATION_GENERATED_DRY_RUN, \
    MESSAGE_FORSETI_CONFIGURATION_GENERATED, DEPLOYMENT_TEMPLATE_OUTPUT_PATH

from utils.gcloud import check_proper_gcloud, \
    create_reuse_service_acct, check_billing_enabled, \
    lookup_organization, get_gcloud_info

from utils.files import copy_file_to_destination, \
    generate_deployment_templates, generate_forseti_conf


class ForsetiInstaller:
    """Forseti installer base class (abstract)"""
    __metaclass__ = ABCMeta

    template_type = None
    branch = None
    project_id = None
    organization_id = None
    access_target = None
    target_id = None
    gcp_service_account = None

    @abstractmethod
    def __init__(self, **kwargs):
        """Init - Child class needs to specify the template_type
            inside this method

        Args:
            kwargs (dict): The kwargs.
        """
        self.datetimestamp = datetime.datetime.now().strftime('%Y%m%d%H%M%S')
        self.timestamp = self.datetimestamp[8:]

        self.force_no_cloudshell = bool(kwargs.get('no_cloudshell'))

        self.config_filename = (kwargs.get('config') or
                                CONFIG_FILENAME_FMT.format(
                                    self.datetimestamp))

        self.advanced_mode = bool(kwargs.get('advanced'))
        self.dry_run = bool(kwargs.get('dry_run'))

        self.bucket_location = kwargs.get('gcs_location') or 'us-central1'

    def run_setup(self):
        """Run the setup steps"""
        print_banner('Forseti %s Setup' % get_forseti_version())

        self.preflight_checks()

        bucket_name = self.generate_bucket_name()
        conf_file_path = self.generate_forseti_conf()
        deployment_tpl_path = self.generate_deployment_templates()

        deploy_success, deployment_name = self.deploy(deployment_tpl_path,
                                                      conf_file_path,
                                                      bucket_name)

        self.post_install_instructions(deploy_success,
                                       deployment_name,
                                       deployment_tpl_path,
                                       conf_file_path,
                                       bucket_name)

    def preflight_checks(self):
        """Pre-flight checks"""
        self.check_run_properties()
        infer_version(self.advanced_mode)
        self.project_id = self.verify_gcloud_get_project_id()
        lookup_organization(self.project_id)
        check_billing_enabled(self.project_id, self.organization_id)
        self.format_gcp_service_acct_id()
        create_reuse_service_acct('gcp_service_account',
                                  self.gcp_service_account,
                                  self.advanced_mode,
                                  self.dry_run)

    def verify_gcloud_get_project_id(self):
        """Verify all the gcloud related information are valid and
        store the project id information inside the class

        Returns:
            str: GCP project id
        """
        check_proper_gcloud()
        project_id, authed_user, is_devshell = get_gcloud_info()
        _check_cloudshell(self.force_no_cloudshell, is_devshell)
        _check_authed_user(authed_user)
        _check_project_id(self.project_id)
        return project_id

    def deploy(self, deploy_tpl_path, conf_file_path, bucket_name):
        """Deploy Forseti using the deployment template

        Args:
            deploy_tpl_path (str): Deployment template path
            conf_file_path (str): Configuration file path
            bucket_name (str): Name of the GCS bucket

        Returns:
            bool: Whether or not the deployment was successful
            str: Deployment name
        """
        deployment_name, return_code = create_deployment(self.project_id,
                                                         self.organization_id,
                                                         deploy_tpl_path,
                                                         self.datetimestamp,
                                                         self.dry_run)
        if not return_code:
            # If deployed successfully, copy configuration file, deployment
            # template file and rule files to the GCS bucket
            conf_output_path = FORSETI_CONF_PATH.format(bucket_name,
                                                        self.template_type)
            copy_file_to_destination(conf_file_path, conf_output_path,
                                     is_directory=False, dry_run=self.dry_run)

            copy_file_to_destination(RULES_DIR_PATH, bucket_name,
                                     is_directory=True, dry_run=self.dry_run)

            dpl_tpl_output_path = self._get_deployment_tpl_gcs_path(bucket_name)
            copy_file_to_destination(deploy_tpl_path, dpl_tpl_output_path,
                                     is_directory=False, dry_run=self.dry_run)

        return not return_code, deployment_name

    def check_run_properties(self):
        """Check script run properties."""
        print('Dry run? %s' % self.dry_run)
        print('Advanced mode? %s' % self.advanced_mode)

    def format_gcp_service_acct_id(self):
        """Format the service account ids."""
        modifier = 'reader'

        self.gcp_service_account = format_service_acct_id('gcp',
                                                          modifier,
                                                          self.timestamp,
                                                          self.project_id)

    def generate_bucket_name(self):
        """Generate bucket name for the rules.

        Returns:
            str: Name of the GCS bucket
        """
        return DEFAULT_BUCKET_FMT.format(
            self.project_id, self.timestamp)

    @abstractmethod
    def get_deployment_values(self):
        """Get deployment values

        Returns:
            dict: A dictionary of values needed to generate
                forseti deployment template
        """
        return {}

    @abstractmethod
    def get_configuration_values(self):
        """Get configuration values

        Returns:
            dict: A dictionary of values needed to generate
                forseti configuration file
        """
        return {}

    def generate_deployment_templates(self):
        """Generate deployment templates.

        Returns:
            str: Deployment template path
        """
        print('Generate Deployment Manager templates...')

        deploy_values = self.get_deployment_values()

        deploy_tpl_path = generate_deployment_templates(
            self.template_type,
            deploy_values,
            self.datetimestamp)

        print('\nCreated a deployment template:\n    %s\n' %
              deploy_tpl_path)
        return deploy_tpl_path

    def generate_forseti_conf(self):
        """Generate Forseti conf file.

        Returns:
            str: Forseti configuration file path
        """
        # Create a forseti_conf_$TIMESTAMP.yaml config file with
        # values filled in.
        # forseti_conf.yaml in file
        print('\nGenerate forseti_conf_%s.yaml...' % self.datetimestamp)

        conf_values = self.get_configuration_values()

        forseti_conf_path = generate_forseti_conf(self.template_type,
                                                  conf_values,
                                                  self.datetimestamp)

        print('\nCreated forseti_conf_%s.yaml config file:\n    %s\n' %
              (self.datetimestamp,
               forseti_conf_path))
        return forseti_conf_path

    def post_install_instructions(self, deploy_success, deployment_name,
                                  deploy_tpl_path, forseti_conf_path,
                                  bucket_name):
        """Show post-install instructions

        Print link for deployment manager dashboard
        Print link to go to G Suite service account and enable DWD

        Args:
            deploy_success (bool): Whether deployment was successful
            deployment_name (str): Name of the deployment
            deploy_tpl_path (str): Deployment template path
            forseti_conf_path (str): Forseti configuration file path
            bucket_name (str): Name of the GCS bucket
        """
        print_banner('Post-setup instructions')

        if self.dry_run:
            print('This was a dry run, so a deployment was not attempted. '
                  'You can still create the deployment manually.\n')
        elif deploy_success:
            print(MESSAGE_FORSETI_BRANCH_DEPLOYED.format(self.branch))
        else:
            print(MESSAGE_DEPLOYMENT_HAD_ISSUES)

        deploy_tpl_gcs_path = self._get_deployment_tpl_gcs_path(bucket_name)

        print(MESSAGE_DEPLOYMENT_TEMPLATE_LOCATION.format(
            deploy_tpl_path, deploy_tpl_gcs_path))

        if self.dry_run:
            print(MESSAGE_FORSETI_CONFIGURATION_GENERATED_DRY_RUN.format(
                forseti_conf_path, bucket_name))
        else:
            print(MESSAGE_VIEW_DEPLOYMENT_DETAILS.format(
                deployment_name,
                self.project_id,
                self.organization_id))

            print(MESSAGE_FORSETI_CONFIGURATION_GENERATED.format(
                self.datetimestamp, bucket_name))

    @staticmethod
    def _get_deployment_tpl_gcs_path(bucket_name):
        """Get deployment template GCS output path

        Args:
            bucket_name (str): Name of the GCS bucket

        Returns:
            str: Deployment template GCS path
        """
        return DEPLOYMENT_TEMPLATE_OUTPUT_PATH \
            .format(bucket_name)


def _check_cloudshell(force_no_cloudshell, is_cloudshell):
    """Check whether using Cloud Shell or bypassing Cloud Shell.

    Args:
        force_no_cloudshell (bool): Whether or not user decided
                                    to not use cloudshell
        is_cloudshell (bool): Whether or not we are using cloudshell
    """
    if not force_no_cloudshell:
        if not is_cloudshell:
            print(MESSAGE_NO_CLOUD_SHELL)
            sys.exit(1)
        else:
            print('Using Cloud Shell, continuing...')
    else:
        print('Bypass Cloud Shell check, continuing...')


def _check_authed_user(authed_user):
    """Get the current authed user.

    Args:
        authed_user (str): Authenticated user
    """
    if not authed_user:
        print('Error getting authed user. You may need to run '
              '"gcloud auth login". Exiting.')
        sys.exit(1)
    print('You are: {}'.format(authed_user))


def _check_project_id(project_id):
    """Get the project.

    Args:
        project_id (str): GCP project id
    """
    if not project_id:
        print('You need to have an active project! Exiting.')
        sys.exit(1)
    print('Project id: %s' % project_id)
