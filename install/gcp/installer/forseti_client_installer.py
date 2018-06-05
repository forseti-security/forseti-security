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

"""Forseti CLI installer."""

from forseti_installer import ForsetiInstaller

from util import gcloud

class ForsetiClientInstaller(ForsetiInstaller):
    """Forseti command line interface installer"""

    def __init__(self, config, previous_installer=None):
        """Init

        Args:
            config (ClientConfig): The configuration object.
            previous_installer (ForsetiInstaller): The previous ran installer,
                we can get the installer environment information from it.
        """
        super(ForsetiClientInstaller, self).__init__(config,
                                                     previous_installer)
        (self.server_ip, self.server_zone,
         self.server_name) = gcloud.get_forseti_server_info()

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
        success, deployment_name = super(ForsetiClientInstaller, self).deploy(
            deployment_tpl_path, conf_file_path, bucket_name)

        if success:
            gcloud.grant_client_svc_acct_roles(
                self.project_id,
                self.gcp_service_acct_email,
                self.user_can_grant_roles)
            instance_name = 'forseti-{}-vm-{}'.format(
                self.config.installation_type,
                self.config.identifier)
            zone = '{}-c'.format(self.config.bucket_location)
            gcloud.enable_os_login(instance_name, zone)
            self.wait_until_vm_initialized(instance_name)
        return success, deployment_name

    def get_configuration_values(self):
        """Get configuration values

        Returns:
            dict: A dictionary of values needed to generate
                the forseti configuration file
        """
        return {
            'SERVER_IP': self.server_ip
        }

    def get_deployment_values(self):
        """Get deployment values

        Returns:
            dict: A dictionary of values needed to generate
                the forseti deployment template
        """
        bucket_name = self.generate_bucket_name()
        return {
            'FORSETI_BUCKET': bucket_name[len('gs://'):],
            'BUCKET_LOCATION': self.config.bucket_location,
            'GCP_CLIENT_SERVICE_ACCOUNT': self.gcp_service_acct_email,
            'FORSETI_TARGET': 'forseti-target: "{}"'.format(self.branch),
            'FORSETI_SERVER_ZONE': self.server_zone
        }
