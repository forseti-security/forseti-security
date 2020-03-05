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

"""Forseti CLI helper class"""

import re
import subprocess


class ForsetiCli:
    """Server Config helper

    Helper class for common functions performed on the Forseti server config
    for end-to-end tests.
    """

    @staticmethod
    def inventory_create(model_name=None):
        """Copy server config from GCS to local path.

        Args:
            model_name (str): Model name to import inventory as

        Returns:
            Tuple(str, subprocess.CompletedProcess): Tuple of Inventory id and result from subprocess.run
        """
        cmd = ['forseti', 'inventory', 'create']
        if model_name:
            cmd.extend(['--import_as', model_name])
        result = subprocess.run(cmd,
                                stderr=subprocess.PIPE,
                                stdout=subprocess.PIPE)
        regex = re.compile('id": "([0-9]*)"')
        match = regex.search(str(result.stdout))
        if match:
            return match.group(1), result
        return '', result

    @staticmethod
    def inventory_delete(inventory_id):
        """Copy server config from GCS to local path.

        Args:
            inventory_id (str): Inventory id to delete

        Returns:
            subprocess.CompletedProcess: Result from subprocess.run
        """
        cmd = ['forseti', 'inventory', 'delete', inventory_id]
        return subprocess.run(cmd, stderr=subprocess.PIPE,
                              stdout=subprocess.PIPE)

    @staticmethod
    def model_create(inventory_id, model_name):
        cmd = ['forseti', 'model', 'create', '--inventory_index_id', inventory_id, model_name]
        return subprocess.run(cmd, stderr=subprocess.PIPE,
                              stdout=subprocess.PIPE)

    @staticmethod
    def model_delete(model_name):
        cmd = ['forseti', 'model', 'delete', model_name]
        return subprocess.run(cmd, stderr=subprocess.PIPE,
                              stdout=subprocess.PIPE)

    @staticmethod
    def model_use(model_name):
        cmd = ['forseti', 'model', 'use', model_name]
        return subprocess.run(cmd, stderr=subprocess.PIPE,
                              stdout=subprocess.PIPE)

    @staticmethod
    def notifier_run(inventory_id=None):
        cmd = ['forseti', 'scanner', 'run']
        if inventory_id:
            cmd.extend(['--inventory_index_id', inventory_id])
        return subprocess.run(cmd, stderr=subprocess.PIPE,
                              stdout=subprocess.PIPE)

    @staticmethod
    def scanner_run():
        cmd = ['forseti', 'scanner', 'run']
        result = subprocess.run(cmd, stderr=subprocess.PIPE,
                                stdout=subprocess.PIPE)
        regex = re.compile('ID: ([0-9]*)')
        match = regex.search(str(result.stdout))
        if match:
            return match.group(1), result
        return '', result
