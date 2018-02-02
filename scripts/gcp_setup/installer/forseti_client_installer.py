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

"""Forseti CLI installer"""

from forseti_installer import ForsetiInstaller

from configs.client_config import ClientConfig
from utils.gcloud import get_forseti_server_info


class ForsetiClientInstaller(ForsetiInstaller):
    """Forseti command line interface installer"""

    # Class variables initialization
    server_ip = ''
    server_zone = ''

    def __init__(self, **kwargs):
        """Init

        Args:
            kwargs (dict): The kwargs.
        """
        super(ForsetiClientInstaller, self).__init__()
        self.config = ClientConfig(**kwargs)
        self.server_ip, self.server_zone = get_forseti_server_info()

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
        return {
            'SCANNER_BUCKET': self.generate_bucket_name()[len('gs://'):],
            'BUCKET_LOCATION': self.config.bucket_location,
            'SERVICE_ACCOUNT_GCP': self.gcp_service_account,
            'BRANCH_OR_RELEASE': 'branch-name: "{}"'.format(self.branch),
            'FORSETI_SERVER_ZONE': self.server_zone
        }
