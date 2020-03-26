# Copyright 2020 The Forseti Security Authors. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Forseti server config helper class"""

import subprocess
import yaml
from google.cloud import storage

CONFIG_GCS_PATH = 'configs/forseti_conf_server.yaml'


class ServerConfig:
    """Server Config helper

    Helper class for common functions performed on the Forseti server config
    for end-to-end tests.
    """

    def __init__(self, path):
        self.server_config_path = path

    def copy_from_gcs(self, bucket_name, object_path=CONFIG_GCS_PATH):
        """Copy server config from GCS to local path.

        Args:
            bucket_name (str): Forseti server bucket name
            object_path (str): Path of the GCS config object

        Returns:
            Blob: Returns GCS blob object of the config copied.
        """
        storage_client = storage.Client()
        bucket = storage_client.bucket(bucket_name)
        blob = bucket.blob(object_path)
        blob.download_to_filename(self.server_config_path)

    def read(self):
        """Read the server config from the local path.

        Returns:
            dict: Returns the server config contents as a dictionary
        """
        with open(self.server_config_path, 'r') as stream:
            return yaml.safe_load(stream)

    @staticmethod
    def reload():
        """Call Forseti to reload the server configuration.

        Returns:
            Nothing
        """
        cmd = ['sudo',
               'forseti',
               'server',
               'configuration',
               'reload']
        subprocess.run(cmd,
                       stderr=subprocess.PIPE,
                       stdout=subprocess.PIPE)

    def write(self, server_config, reload=True):
        """Write server config from GCS to local path.

        Args:
            server_config (dict): Server config to write
            reload (bool): Control whether Forseti server config is reloaded after writing

        Returns:
            Nothing
        """
        with open(self.server_config_path, 'w', encoding='utf8') as outfile:
            yaml.dump(server_config,
                      outfile,
                      allow_unicode=True,
                      default_style=None,
                      default_flow_style=False)
        if reload:
            ServerConfig.reload()
