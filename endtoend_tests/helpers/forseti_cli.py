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
    """Forseti CLI helper

    Run common commands with the Forseti CLI.
    """

    @staticmethod
    def config_show():
        cmd = ['forseti', 'config', 'show']
        return subprocess.run(cmd, stderr=subprocess.PIPE,
                              stdout=subprocess.PIPE)

    @staticmethod
    def explainer_access_by_authz(permission=None, role=None):
        cmd = ['forseti', 'explainer', 'access_by_authz']
        if permission:
            cmd.extend(['--permission', permission])
        elif role:
            cmd.extend(['--role', role])
        else:
            raise ValueError('Permission or role argument required.')
        return subprocess.run(cmd, stderr=subprocess.PIPE,
                              stdout=subprocess.PIPE)

    @staticmethod
    def explainer_access_by_member(member, permissions=None):
        cmd = ['forseti', 'explainer', 'access_by_member', member]
        if permissions:
            cmd.extend(permissions)
        return subprocess.run(cmd, stderr=subprocess.PIPE,
                              stdout=subprocess.PIPE)

    @staticmethod
    def explainer_access_by_resource(resource, grep=None):
        cmd = ['forseti', 'explainer', 'access_by_resource', resource]
        if grep:
            cmd.extend(['|', 'grep', '-c', grep])
        return subprocess.run(cmd, stderr=subprocess.PIPE,
                              stdout=subprocess.PIPE)

    @staticmethod
    def explainer_check_policy(resource, policy, member):
        cmd = ['forseti', 'explainer', 'check_policy', resource, policy,
               member]
        return subprocess.run(cmd, stderr=subprocess.PIPE,
                              stdout=subprocess.PIPE)

    @staticmethod
    def inventory_create(model_name=None):
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
        cmd = ['forseti', 'inventory', 'delete', inventory_id]
        return subprocess.run(cmd, stderr=subprocess.PIPE,
                              stdout=subprocess.PIPE)

    @staticmethod
    def model_create(inventory_id, model_name):
        cmd = ['forseti', 'model', 'create', '--inventory_index_id',
               inventory_id, model_name]
        result = subprocess.run(cmd, stderr=subprocess.PIPE,
                                stdout=subprocess.PIPE)
        regex = re.compile('handle": "([0-9]*)"')
        match = regex.search(str(result.stdout))
        if match:
            return match.group(1), result
        return '', result

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
